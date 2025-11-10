/*
 * Copyright 2023-2025 Trustify Dependency Analytics Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.guacsec.trustifyda.integration.providers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangeProperty;
import org.apache.camel.RuntimeCamelException;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.jboss.logging.Logger;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.DependencyReport;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.ProviderStatus;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.api.v5.SourceSummary;
import io.github.guacsec.trustifyda.api.v5.TransitiveDependencyReport;
import io.github.guacsec.trustifyda.config.exception.PackageValidationException;
import io.github.guacsec.trustifyda.config.exception.UnexpectedProviderException;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.CvssScoreComparable.DependencyScoreComparator;
import io.github.guacsec.trustifyda.model.CvssScoreComparable.TransitiveScoreComparator;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.github.guacsec.trustifyda.monitoring.MonitoringProcessor;
import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

@RegisterForReflection
@ApplicationScoped
public abstract class ProviderResponseHandler {

  private static final Logger LOGGER = Logger.getLogger(ProviderResponseHandler.class);

  @Inject MonitoringProcessor monitoringProcessor;

  protected abstract String getProviderName(Exchange exchange);

  public abstract ProviderResponse responseToIssues(byte[] response, DependencyTree tree)
      throws IOException;

  public ProviderResponse aggregateSplit(ProviderResponse oldExchange, ProviderResponse newExchange)
      throws IOException {
    if (oldExchange == null) {
      return newExchange;
    }
    if (oldExchange.status() != null && !Boolean.TRUE.equals(oldExchange.status().getOk())) {
      return oldExchange;
    }
    var exchange = new ProviderResponse(new HashMap<>(), oldExchange.status());

    if (oldExchange.pkgItems() != null) {
      exchange.pkgItems().putAll(oldExchange.pkgItems());
    }
    if (newExchange.pkgItems() != null) {
      exchange
          .pkgItems()
          .entrySet()
          .forEach(
              e -> {
                var item = newExchange.pkgItems().get(e.getKey());
                if (item != null) {
                  e.getValue().issues().addAll(item.issues());
                }
              });

      newExchange.pkgItems().keySet().stream()
          .filter(k -> !exchange.pkgItems().keySet().contains(k))
          .forEach(
              k -> {
                exchange.pkgItems().put(k, newExchange.pkgItems().get(k));
              });
    } else if (Boolean.FALSE.equals(newExchange.status().getOk())) {
      return new ProviderResponse(exchange.pkgItems(), newExchange.status());
    }
    return exchange;
  }

  protected ProviderStatus defaultOkStatus(String provider) {
    return new ProviderStatus()
        .name(provider)
        .ok(Boolean.TRUE)
        .message(Response.Status.OK.getReasonPhrase())
        .code(Response.Status.OK.getStatusCode());
  }

  protected DependencyReport toDependencyReport(PackageRef ref, List<Issue> issues) {
    return new DependencyReport()
        .ref(ref)
        .issues(
            issues.stream()
                .sorted(Comparator.comparing(Issue::getCvssScore).reversed())
                .collect(Collectors.toList()));
  }

  public ProviderReport unauthenticatedResponse(Exchange exchange) {
    var providerName = getProviderName(exchange);
    return new ProviderReport()
        .status(
            new ProviderStatus()
                .name(providerName)
                .ok(Boolean.FALSE)
                .message(Constants.HTTP_UNAUTHENTICATED)
                .code(Response.Status.UNAUTHORIZED.getStatusCode()));
  }

  public void processResponseError(Exchange exchange) {
    var providerName = getProviderName(exchange);
    ProviderStatus status = new ProviderStatus().ok(false).name(providerName);
    Exception exception = (Exception) exchange.getProperty(Exchange.EXCEPTION_CAUGHT);

    Throwable cause = exception != null ? exception.getCause() : null;

    while (cause instanceof RuntimeCamelException) {
      cause = cause.getCause();
    }
    if (cause == null) {
      cause = exception;
    }
    if (cause instanceof HttpOperationFailedException httpException) {
      String message = prettifyHttpError(httpException);
      status.message(message).code(httpException.getStatusCode());
      LOGGER.warn("Unable to process request: {}", message, cause);
    } else if (cause instanceof IllegalArgumentException
        || cause instanceof UnexpectedProviderException
        || cause instanceof PackageValidationException) {
      status.message(cause.getMessage()).code(422);
      LOGGER.debug("Unable to process request to: {}", providerName, exception);
    } else {
      status
          .message(cause.getMessage())
          .code(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
      LOGGER.warn("Unable to process request to: {}", providerName, cause);
    }
    ProviderResponse response = new ProviderResponse(null, status);
    monitoringProcessor.processProviderError(exchange, exception, providerName);
    exchange.getMessage().setBody(response);
  }

  public void processTokenFallBack(Exchange exchange) {
    Exception exception = (Exception) exchange.getProperty(Exchange.EXCEPTION_CAUGHT);
    var providerName = getProviderName(exchange);
    Throwable cause = exception;
    if (exception.getCause() != null) {
      cause = exception.getCause();
    }
    String body;
    int code = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();

    switch (cause) {
      case WebApplicationException webException -> {
        code = webException.getResponse().getStatus();
        body = webException.getMessage();
      }
      case HttpOperationFailedException httpException -> {
        code = httpException.getStatusCode();
        if (code == Response.Status.UNAUTHORIZED.getStatusCode()) {
          body = "Invalid token provided. Unauthorized";
        } else {
          body = "Unable to validate " + providerName + " Token: " + httpException.getStatusText();
        }
      }
      default -> body = "Unable to validate " + providerName + " Token: " + cause.getMessage();
    }
    exchange.getMessage().setHeader(Exchange.HTTP_RESPONSE_CODE, code);
    exchange.getMessage().setBody(body);
  }

  private static String prettifyHttpError(HttpOperationFailedException httpException) {
    String text = httpException.getStatusText();
    String defaultReason =
        httpException.getResponseBody() != null
            ? httpException.getResponseBody()
            : httpException.getMessage();
    return text
        + switch (httpException.getStatusCode()) {
          case 401 -> ": Verify the provided credentials are valid.";
          case 403 -> ": The provided credentials don't have the required permissions.";
          case 429 -> ": The rate limit has been exceeded.";
          default -> ": " + defaultReason;
        };
  }

  public ProviderResponse emptyResponse(
      @ExchangeProperty(Constants.DEPENDENCY_TREE_PROPERTY) DependencyTree tree) {
    return new ProviderResponse(Collections.emptyMap(), null);
  }

  /**
   * Groups PackageItems by source from their issues. Each PackageItem can have issues from
   * different sources, so we group them accordingly while preserving recommendations.
   */
  private Map<String, Map<String, PackageItem>> groupPackageItemsBySource(
      Map<String, PackageItem> pkgItems, String defaultSource) {
    Map<String, Map<String, PackageItem>> sourcesData = new HashMap<>();
    if (pkgItems == null) {
      return sourcesData;
    }

    var recommendations =
        pkgItems.values().stream()
            .filter(item -> item.recommendation() != null)
            .collect(Collectors.toMap(PackageItem::packageRef, PackageItem::recommendation));

    pkgItems.forEach(
        (packageRef, packageItem) -> {
          // If there are issues, group by their source
          if (packageItem.issues() != null && !packageItem.issues().isEmpty()) {
            packageItem
                .issues()
                .forEach(
                    issue -> {
                      String source = issue.getSource();
                      if (source == null) {
                        return;
                      }
                      var sourceItems = sourcesData.computeIfAbsent(source, k -> new HashMap<>());
                      // Get or create PackageItem for this source and package
                      var existingItem = sourceItems.get(packageRef);
                      var recommendation = recommendations.get(packageRef);
                      if (existingItem == null) {
                        // Create new PackageItem with this issue and the recommendation
                        sourceItems.put(
                            packageRef,
                            new PackageItem(
                                packageRef, recommendation, new ArrayList<>(List.of(issue))));
                      } else {
                        // Add issue to existing PackageItem if not already present
                        if (!existingItem.issues().contains(issue)) {
                          var updatedIssues = new ArrayList<>(existingItem.issues());
                          updatedIssues.add(issue);

                          sourceItems.put(
                              packageRef,
                              new PackageItem(packageRef, recommendation, updatedIssues));
                        }
                      }
                    });
          }
        });
    if (sourcesData.isEmpty() && !recommendations.isEmpty()) {
      sourcesData.put(defaultSource, new HashMap<>());
    }
    sourcesData.forEach(
        (source, items) -> {
          recommendations.forEach(
              (packageRef, recommendation) -> {
                if (!items.containsKey(packageRef)) {
                  items.put(
                      packageRef,
                      new PackageItem(packageRef, recommendation, Collections.emptyList()));
                }
              });
        });
    return sourcesData;
  }

  public ProviderReport buildReport(
      Exchange exchange,
      @Body ProviderResponse response,
      @ExchangeProperty(Constants.DEPENDENCY_TREE_PROPERTY) DependencyTree tree)
      throws IOException {
    if (response.status() != null) {
      return new ProviderReport().status(response.status()).sources(Collections.emptyMap());
    }
    var providerName = getProviderName(exchange);
    var sourcesData = groupPackageItemsBySource(response.pkgItems(), providerName);

    Map<String, Source> reports = new HashMap<>();
    sourcesData
        .entrySet()
        .forEach(
            entry -> reports.put(entry.getKey(), buildReportForSource(entry.getValue(), tree)));
    return new ProviderReport().status(defaultOkStatus(providerName)).sources(reports);
  }

  private Source buildReportForSource(Map<String, PackageItem> pkgItemsData, DependencyTree tree) {
    List<DependencyReport> sourceReport = new ArrayList<>();
    Set<String> processedRefs = new HashSet<>();

    // Process packages from the dependency tree
    tree.dependencies().entrySet().stream()
        .forEach(
            depEntry -> {
              var packageRef = depEntry.getKey();
              processedRefs.add(packageRef.ref());
              var packageItem = getPackageItem(packageRef, pkgItemsData);
              var directReport = new DependencyReport().ref(packageRef);

              setIssues(packageItem, directReport);
              setRecommendations(packageItem, directReport);

              List<TransitiveDependencyReport> transitiveReports =
                  depEntry.getValue().transitive().stream()
                      .map(
                          t -> {
                            return getTransitiveReport(pkgItemsData, directReport, t);
                          })
                      .filter(transitiveReport -> !transitiveReport.getIssues().isEmpty())
                      .collect(Collectors.toList());
              transitiveReports.sort(Collections.reverseOrder(new TransitiveScoreComparator()));
              directReport.setTransitive(transitiveReports);
              if (directReport.getHighestVulnerability() != null
                  || directReport.getRecommendation() != null) {
                sourceReport.add(directReport);
              }
            });

    if (pkgItemsData != null) {
      addRecommendationsWithoutIssues(pkgItemsData, sourceReport, processedRefs);
    }

    sourceReport.sort(Collections.reverseOrder(new DependencyScoreComparator()));
    var summary = buildSummary(pkgItemsData, tree, sourceReport);
    return new Source().summary(summary).dependencies(sourceReport);
  }

  private void addRecommendationsWithoutIssues(
      Map<String, PackageItem> pkgItemsData,
      List<DependencyReport> sourceReport,
      Set<String> processedRefs) {
    pkgItemsData.entrySet().stream()
        .filter(
            entry -> {
              var packageItem = entry.getValue();
              // Include if it has a recommendation but no issues and wasn't already processed
              return !processedRefs.contains(entry.getKey())
                  && (packageItem.issues() == null || packageItem.issues().isEmpty())
                  && packageItem.recommendation() != null
                  && packageItem.recommendation().packageName() != null;
            })
        .forEach(
            entry -> {
              try {
                var packageRef = new PackageRef(entry.getKey());
                var packageItem = entry.getValue();
                var directReport = new DependencyReport().ref(packageRef);
                directReport.recommendation(packageItem.recommendation().packageName());
                sourceReport.add(directReport);
              } catch (Exception e) {
                // Skip if packageRef cannot be created from the string
                // This shouldn't happen but handle gracefully
              }
            });
  }

  private TransitiveDependencyReport getTransitiveReport(
      Map<String, PackageItem> pkgItemsData, DependencyReport directReport, PackageRef t) {
    var transitiveItem = getPackageItem(t, pkgItemsData);
    List<Issue> transitiveIssues = Collections.emptyList();
    if (transitiveItem != null
        && transitiveItem.issues() != null
        && !transitiveItem.issues().isEmpty()) {
      transitiveIssues =
          transitiveItem.issues().stream()
              .sorted(Comparator.comparing(Issue::getCvssScore).reversed())
              .collect(Collectors.toList());
    }
    var highestTransitive = transitiveIssues.stream().findFirst();
    if (highestTransitive.isPresent()) {
      if (directReport.getHighestVulnerability() == null
          || directReport.getHighestVulnerability().getCvssScore()
              < highestTransitive.get().getCvssScore()) {
        directReport.setHighestVulnerability(highestTransitive.get());
      }
    }
    var transitiveReport =
        new TransitiveDependencyReport()
            .ref(t)
            .issues(transitiveIssues)
            .highestVulnerability(highestTransitive.orElse(null));
    // Note: TransitiveDependencyReport doesn't have a recommendation field
    // Recommendations are only set on direct dependencies
    return transitiveReport;
  }

  private void setRecommendations(PackageItem packageItem, DependencyReport directReport) {
    if (packageItem != null
        && packageItem.recommendation() != null
        && packageItem.recommendation().packageName() != null) {
      directReport.recommendation(packageItem.recommendation().packageName());
    }
  }

  private void setIssues(PackageItem packageItem, DependencyReport directReport) {
    if (packageItem != null && packageItem.issues() != null && !packageItem.issues().isEmpty()) {
      var issues =
          packageItem.issues().stream()
              .sorted(Comparator.comparing(Issue::getCvssScore).reversed())
              .collect(Collectors.toList());
      directReport.issues(issues);
      directReport.setHighestVulnerability(issues.stream().findFirst().orElse(null));
    }
  }

  private PackageItem getPackageItem(PackageRef ref, Map<String, PackageItem> pkgItemsData) {
    return pkgItemsData.get(ref.ref());
  }

  private SourceSummary buildSummary(
      Map<String, PackageItem> issuesData,
      DependencyTree tree,
      List<DependencyReport> sourceReport) {
    var counter = new VulnerabilityCounter();
    var directRefs =
        tree.dependencies().keySet().stream().map(PackageRef::ref).collect(Collectors.toSet());
    issuesData
        .entrySet()
        .forEach(e -> incrementCounter(e.getValue(), counter, directRefs.contains(e.getKey())));
    Long recommendationsCount =
        sourceReport.stream().filter(s -> s.getRecommendation() != null).count();
    counter.recommendations.set(recommendationsCount.intValue());
    return counter.getSummary();
  }

  private void incrementCounter(PackageItem item, VulnerabilityCounter counter, boolean isDirect) {
    if (item != null && !item.issues().isEmpty()) {
      counter.dependencies.incrementAndGet();
    }
    if (item.issues() == null) {
      return;
    }
    item.issues().stream()
        .filter(Objects::nonNull)
        .forEach(
            i -> {
              var vulnerabilities = countVulnerabilities(i);
              var severity = i.getSeverity();
              if (severity != null) {
                switch (severity) {
                  case CRITICAL -> counter.critical.addAndGet(vulnerabilities);
                  case HIGH -> counter.high.addAndGet(vulnerabilities);
                  case MEDIUM -> counter.medium.addAndGet(vulnerabilities);
                  case LOW -> counter.low.addAndGet(vulnerabilities);
                }
              }
              counter.total.addAndGet(vulnerabilities);
              if (isDirect) {
                counter.direct.addAndGet(vulnerabilities);
              }
              if (i.getRemediation() != null
                  && i.getRemediation().getTrustedContent() != null
                  && i.getRemediation().getTrustedContent().getRef() != null) {
                counter.remediations.incrementAndGet();
              }
            });
  }

  // The number of vulnerabilities is the total count of public CVEs
  // or if it is private it will be 1
  private int countVulnerabilities(Issue i) {
    if (i.getCves() != null && !i.getCves().isEmpty()) {
      return i.getCves().size();
    }
    if (i.getUnique() != null && i.getUnique()) {
      return 1;
    }
    return 0;
  }

  private static final record VulnerabilityCounter(
      AtomicInteger total,
      AtomicInteger critical,
      AtomicInteger high,
      AtomicInteger medium,
      AtomicInteger low,
      AtomicInteger direct,
      AtomicInteger dependencies,
      AtomicInteger remediations,
      AtomicInteger recommendations) {

    VulnerabilityCounter() {
      this(
          new AtomicInteger(),
          new AtomicInteger(),
          new AtomicInteger(),
          new AtomicInteger(),
          new AtomicInteger(),
          new AtomicInteger(),
          new AtomicInteger(),
          new AtomicInteger(),
          new AtomicInteger());
    }

    SourceSummary getSummary() {
      return new SourceSummary()
          .total(total.get())
          .critical(critical.get())
          .high(high.get())
          .medium(medium.get())
          .low(low.get())
          .direct(direct.get())
          .transitive(total.get() - direct.get())
          .dependencies(dependencies.get())
          .remediations(remediations.get())
          .recommendations(recommendations.get());
    }
  }
}
