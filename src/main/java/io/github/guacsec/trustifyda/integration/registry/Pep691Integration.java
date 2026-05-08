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

package io.github.guacsec.trustifyda.integration.registry;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.DependencyReport;
import io.github.guacsec.trustifyda.api.v5.Remediation;
import io.github.guacsec.trustifyda.api.v5.RemediationTrustedContent;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.registry.Pep691Response;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;

@ApplicationScoped
public class Pep691Integration extends EndpointRouteBuilder {

  private static final Logger LOGGER = Logger.getLogger(Pep691Integration.class);

  private static final String PEP691_ACCEPT = "application/vnd.pypi.simple.v1+json";
  private static final String PKG_PYPI_PREFIX = "pkg:pypi/";
  private static final String HASH_ALG_SHA256 = "SHA-256";
  private static final String PEP691_URL_PROPERTY = "pep691RegistryUrl";
  private static final String PEP691_PACKAGE_PROPERTY = "pep691PackageName";

  @ConfigProperty(name = "api.pypi.registry.host", defaultValue = "")
  String registryHost;

  @ConfigProperty(name = "api.pypi.registry.timeout", defaultValue = "10s")
  String timeout;

  @Inject ObjectMapper objectMapper;

  @Inject ProducerTemplate producerTemplate;

  @Override
  public void configure() {
    // fmt:off
    from(direct("enrichPypiRecommendations"))
      .routeId("enrichPypiRecommendations")
      .process(this::enrichRecommendations);

    from(direct("pep691Lookup"))
      .routeId("pep691Lookup")
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .process(this::processPep691Request)
        .toD("${exchangeProperty.pep691RegistryUrl}?throwExceptionOnFailure=false")
      .onFallback()
        .process(this::handleLookupFallback)
      .end();
    // fmt:on
  }

  private void processPep691Request(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_RAW_QUERY);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Exchange.HTTP_PATH);
    message.removeHeader(Exchange.HTTP_HOST);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.removeHeader(Exchange.CONTENT_TYPE);

    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.GET);
    message.setHeader("Accept", PEP691_ACCEPT);

    String packageName = exchange.getProperty(PEP691_PACKAGE_PROPERTY, String.class);
    message.setHeader(Exchange.HTTP_PATH, "/" + packageName + "/");
  }

  private void handleLookupFallback(Exchange exchange) {
    exchange.getMessage().setHeader(Exchange.HTTP_RESPONSE_CODE, 504);
    exchange.getMessage().setBody(null);
  }

  void enrichRecommendations(Exchange exchange) {
    if (registryHost == null || registryHost.isBlank()) {
      return;
    }

    var body = exchange.getIn().getBody();
    if (!(body instanceof AnalysisReport report)) {
      return;
    }

    DependencyTree tree =
        exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class);
    if (tree == null) {
      return;
    }

    Map<String, Map<String, String>> hashes = tree.componentHashes();
    var providers = report.getProviders();
    if (providers == null || providers.isEmpty()) {
      return;
    }

    Set<String> processedPurls = new HashSet<>();

    for (var providerEntry : providers.entrySet()) {
      var providerReport = providerEntry.getValue();
      if (providerReport == null
          || providerReport.getSources() == null
          || providerReport.getSources().isEmpty()) {
        continue;
      }

      for (var sourceEntry : providerReport.getSources().entrySet()) {
        var sourceReport = sourceEntry.getValue();
        if (sourceReport == null || sourceReport.getDependencies() == null) {
          continue;
        }

        for (var depReport : sourceReport.getDependencies()) {
          if (depReport == null || depReport.getRef() == null) {
            continue;
          }

          String purlRef = depReport.getRef().ref();
          if (purlRef == null || !purlRef.startsWith(PKG_PYPI_PREFIX)) {
            continue;
          }

          processedPurls.add(purlRef);

          if (depReport.getRecommendation() != null) {
            continue;
          }

          Map<String, String> purlHashes = hashes.get(purlRef);
          String sbomSha256 = (purlHashes != null) ? purlHashes.get(HASH_ALG_SHA256) : null;
          Optional<PackageRef> recommendedRef = queryRegistryAndCompare(purlRef, sbomSha256);
          if (recommendedRef.isEmpty()) {
            continue;
          }

          var trustedContent = new RemediationTrustedContent().ref(recommendedRef.get());

          if (depReport.getIssues() != null) {
            depReport
                .getIssues()
                .forEach(
                    issue -> issue.remediation(new Remediation().trustedContent(trustedContent)));
          }

          depReport.recommendation(recommendedRef.get());
        }
      }
    }

    for (PackageRef pkgRef : tree.getAll()) {
      String purlRef = pkgRef.ref();
      if (purlRef == null || !purlRef.startsWith(PKG_PYPI_PREFIX)) {
        continue;
      }
      if (processedPurls.contains(purlRef)) {
        continue;
      }

      Map<String, String> purlHashes = hashes.get(purlRef);
      String sbomSha256 = (purlHashes != null) ? purlHashes.get(HASH_ALG_SHA256) : null;
      Optional<PackageRef> recommendedRef = queryRegistryAndCompare(purlRef, sbomSha256);
      if (recommendedRef.isEmpty()) {
        continue;
      }

      var depReport = new DependencyReport().ref(pkgRef).recommendation(recommendedRef.get());

      for (var providerEntry : providers.entrySet()) {
        var providerReport = providerEntry.getValue();
        if (providerReport == null
            || providerReport.getSources() == null
            || providerReport.getSources().isEmpty()) {
          continue;
        }
        for (var sourceEntry : providerReport.getSources().entrySet()) {
          var sourceReport = sourceEntry.getValue();
          if (sourceReport != null) {
            sourceReport.addDependenciesItem(depReport);
            break;
          }
        }
        break;
      }
    }

    for (var providerEntry : providers.entrySet()) {
      var providerReport = providerEntry.getValue();
      if (providerReport == null || providerReport.getSources() == null) {
        continue;
      }
      for (var sourceEntry : providerReport.getSources().entrySet()) {
        var sourceReport = sourceEntry.getValue();
        if (sourceReport == null
            || sourceReport.getDependencies() == null
            || sourceReport.getSummary() == null) {
          continue;
        }
        int recCount =
            (int)
                sourceReport.getDependencies().stream()
                    .filter(d -> d.getRecommendation() != null)
                    .count();
        sourceReport.getSummary().setRecommendations(recCount);
      }
    }
  }

  Optional<PackageRef> queryRegistryAndCompare(String purlRef, String sbomSha256) {
    try {
      PackageRef ref = PackageRef.builder().purl(purlRef).build();
      String name = ref.name();
      String version = ref.version();
      if (name == null || version == null) {
        return Optional.empty();
      }

      String normalizedName = name.toLowerCase().replace("-", "_").replace(".", "_");
      String baseUrl = registryHost.replaceAll("/+$", "");

      Exchange response =
          producerTemplate.send(
              "direct:pep691Lookup",
              ex -> {
                ex.setProperty(PEP691_URL_PROPERTY, baseUrl);
                ex.setProperty(PEP691_PACKAGE_PROPERTY, normalizedName);
              });

      Integer statusCode =
          response.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE, Integer.class);
      if (statusCode == null || statusCode != 200) {
        LOGGER.debugf("PEP 691 registry returned %s for %s", statusCode, name);
        return Optional.empty();
      }

      String responseBody = response.getMessage().getBody(String.class);
      Pep691Response pep691Response = objectMapper.readValue(responseBody, Pep691Response.class);
      if (pep691Response == null
          || pep691Response.files() == null
          || pep691Response.files().isEmpty()) {
        return Optional.empty();
      }

      String filePrefix = normalizedName + "-" + version;
      for (var file : pep691Response.files()) {
        if (file.filename() == null || file.hashes() == null) {
          continue;
        }
        if (!matchesVersion(file.filename(), filePrefix)) {
          continue;
        }
        String registrySha256 = file.hashes().get("sha256");
        if (registrySha256 != null) {
          if (sbomSha256 != null && registrySha256.equalsIgnoreCase(sbomSha256)) {
            return Optional.empty();
          }
          return Optional.of(
              PackageRef.builder()
                  .purl(PKG_PYPI_PREFIX + name + "@" + version + "?repository_url=" + baseUrl)
                  .build());
        }
      }

      return Optional.empty();
    } catch (Exception e) {
      LOGGER.debugf("PEP 691 registry lookup failed for %s: %s", purlRef, e.getMessage());
      return Optional.empty();
    }
  }

  private boolean matchesVersion(String filename, String prefix) {
    String normalizedFilename = filename.toLowerCase().replace("-", "_").replace(".", "_");
    String normalizedPrefix = prefix.toLowerCase().replace("-", "_").replace(".", "_");
    if (!normalizedFilename.startsWith(normalizedPrefix)) {
      return false;
    }
    if (normalizedFilename.length() == normalizedPrefix.length()) {
      return true;
    }
    char next = filename.charAt(prefix.length());
    return next == '-' || next == '.' || next == '_';
  }
}
