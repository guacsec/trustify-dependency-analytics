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

package io.github.guacsec.trustifyda.integration.licenses;

import static io.github.guacsec.trustifyda.api.v5.LicenseInfo.CategoryEnum;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.camel.Exchange;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import io.github.guacsec.trustifyda.api.v5.LicenseInfo;
import io.github.guacsec.trustifyda.api.v5.LicenseProviderResult;
import io.github.guacsec.trustifyda.api.v5.LicensesSummary;
import io.github.guacsec.trustifyda.api.v5.PackageLicenseResult;
import io.github.guacsec.trustifyda.api.v5.ProviderStatus;
import io.github.guacsec.trustifyda.integration.backend.BackendUtils;
import io.github.guacsec.trustifyda.model.licenses.LicenseConfig;
import io.github.guacsec.trustifyda.model.licenses.LicenseSplitResult;
import io.github.guacsec.trustifyda.monitoring.MonitoringProcessor;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class DepsDevResponseHandler {

  @ConfigProperty(name = "licenses.file", defaultValue = "licenses.yaml")
  String licensesFile;

  @ConfigProperty(name = "api.licenses.depsdev.host", defaultValue = "https://api.deps.dev/")
  String depsDevHost;

  private static final String DEPS_DEV_SOURCE = "deps.dev";

  private static final Logger LOGGER = Logger.getLogger(DepsDevResponseHandler.class);

  @Inject ObjectMapper mapper;

  @Inject MonitoringProcessor monitoringProcessor;

  private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

  private LicenseConfig licenseConfig;

  @PostConstruct
  public void init() {
    var file = getClass().getClassLoader().getResourceAsStream(licensesFile);
    try {
      if (file != null) {
        licenseConfig = YAML_MAPPER.readValue(file, LicenseConfig.class);
      } else {
        LOGGER.info("Licenses config not found on classpath: " + licensesFile);
        licenseConfig = YAML_MAPPER.readValue(new File(licensesFile), LicenseConfig.class);
      }
    } catch (IOException ex) {
      LOGGER.error("Error loading licenses file", ex);
    }

    if (licenseConfig == null) {
      throw new RuntimeException("Licenses config not found on classpath: " + licensesFile);
    }
  }

  public void handleResponse(Exchange exchange) {
    try {
      var body = exchange.getIn().getBody(String.class);
      if (body == null || body.isBlank()) {
        throw new RuntimeException("Empty response from Deps.dev licenses API");
      }
      var results = new HashMap<String, PackageLicenseResult>();

      var json = mapper.readTree(body);
      if (!json.has("responses") || !json.get("responses").isArray()) {
        throw new RuntimeException("Invalid response format: missing or non-array 'responses'");
      }
      var responses = (ArrayNode) json.get("responses");
      responses.forEach(
          response -> {
            var infos = new ArrayList<LicenseInfo>();
            var request = (ObjectNode) response.get("request");
            var purl = request.get("purl").asText();
            if (response.has("result")) {

              var result = (ObjectNode) response.get("result");
              if (result.has("version")) {
                var version = result.get("version");
                var licensesNode = (ArrayNode) version.get("licenseDetails");
                licensesNode.forEach(
                    licenseNode -> {
                      var info = new LicenseInfo();
                      var spdx = licenseNode.get("spdx").asText();
                      info.identifiers(splitLicenses(spdx));
                      info.category(resolveCategory(spdx));
                      info.expression(spdx);
                      info.name(licenseNode.get("license").asText());
                      info.source(DEPS_DEV_SOURCE);
                      info.sourceUrl(depsDevHost);
                      infos.add(info);
                    });
              }
            }

            var packageResult =
                new PackageLicenseResult().concluded(getConcluded(infos)).evidence(infos);
            results.put(purl, packageResult);
          });
      exchange
          .getMessage()
          .setBody(
              new LicenseSplitResult(
                  new ProviderStatus().ok(true).name(DEPS_DEV_SOURCE).message("OK"), results));
    } catch (JsonProcessingException ex) {
      LOGGER.error("Error parsing JSON response", ex);
      throw new RuntimeException("Error parsing JSON response", ex);
    }
  }

  public LicenseSplitResult aggregateLicenses(
      LicenseSplitResult oldResult, LicenseSplitResult newResult) {
    if (oldResult == null) {
      return newResult;
    }
    Map<String, PackageLicenseResult> mergedPackages = new HashMap<>(oldResult.packages());
    if (newResult != null) {
      mergedPackages.putAll(newResult.packages());
    }
    var status = getWorstStatus(oldResult, newResult);
    return new LicenseSplitResult(status, mergedPackages);
  }

  private ProviderStatus getWorstStatus(
      LicenseSplitResult oldResult, LicenseSplitResult newResult) {
    if (oldResult == null) {
      if (newResult == null) {
        return null;
      }
      return newResult.status();
    }
    if (newResult == null) {
      return oldResult.status();
    }
    // If the old status is not OK, propagate the failure. Otherwise, use the new status.
    return !oldResult.status().getOk() ? oldResult.status() : newResult.status();
  }

  public List<LicenseProviderResult> toResultList(LicenseSplitResult results) {
    var response = new LicenseProviderResult();
    response.packages(results.packages());
    response.summary(buildSummary(results.packages()));
    response.status(results.status());

    return List.of(response);
  }

  public void processResponseError(Exchange exchange) {
    var result = BackendUtils.getErrorMappingFromExchange(exchange);
    var status =
        new ProviderStatus()
            .ok(false)
            .name(DEPS_DEV_SOURCE)
            .message(result.mapping().message())
            .code(result.mapping().statusCode());
    LOGGER.warnf(
        "Unable to process request to Deps.dev licenses API: %s", result.mapping().message());
    monitoringProcessor.processProviderError(exchange, result.exception(), DEPS_DEV_SOURCE);
    exchange.getMessage().setBody(new LicenseSplitResult(status, Collections.emptyMap()));
  }

  private List<String> splitLicenses(String spdxLicense) {
    var licenses = new ArrayList<String>();
    var parts = spdxLicense.split("( AND | OR )");
    for (var part : parts) {
      var license = part.trim();
      licenses.add(license);
    }
    return licenses;
  }

  private CategoryEnum resolveCategory(String spdxLicense) {
    var isOrExpression = spdxLicense.contains(" OR ");

    var licenses = splitLicenses(spdxLicense);
    CategoryEnum category = null;

    for (var license : licenses) {
      var newCategory = getCategory(license);
      if (category == null) {
        category = newCategory;
      } else {
        if (isOrExpression) {
          if (isMorePermissive(newCategory, category)) {
            category = newCategory;
          }
        } else {
          if (isMorePermissive(category, newCategory)) {
            category = newCategory;
          }
        }
      }
    }
    return category;
  }

  private CategoryEnum getCategory(String license) {
    var baseLicense = license;
    String suffix = null;
    if (license.endsWith("-only")) {
      baseLicense = license.substring(0, license.length() - "-only".length());
    }
    if (license.endsWith("-or-later")) {
      baseLicense = license.substring(0, license.length() - "-or-later".length());
    }
    if (license.contains("-with-")) {
      baseLicense = license.substring(0, license.indexOf("-with-"));
      suffix = license.substring(license.indexOf("-with-") + "-with-".length());
    }
    if (licenseConfig.permissive().contains(baseLicense)) {
      return CategoryEnum.PERMISSIVE;
    }
    if (licenseConfig.weakCopyleft().contains(baseLicense)) {
      return CategoryEnum.WEAK_COPYLEFT;
    }
    if (licenseConfig.strongCopyleft().contains(baseLicense)) {
      if (suffix != null && licenseConfig.exceptionSuffixes().contains(suffix)) {
        return CategoryEnum.WEAK_COPYLEFT;
      }
      return CategoryEnum.STRONG_COPYLEFT;
    }
    return CategoryEnum.UNKNOWN;
  }

  /** Returns true if category1 is more permissive than category2. */
  private boolean isMorePermissive(CategoryEnum category1, CategoryEnum category2) {
    if (category1 == category2) {
      return false; // Neither is more permissive than the other
    }
    return getCategoryRank(category1) > getCategoryRank(category2);
  }

  private int getCategoryRank(CategoryEnum category) {
    if (category == null) {
      return -1; // Lowest rank
    }
    return switch (category) {
      case PERMISSIVE -> 4;
      case WEAK_COPYLEFT -> 3;
      case STRONG_COPYLEFT -> 2;
      case UNKNOWN -> 1;
      default -> 0;
    };
  }

  private LicensesSummary buildSummary(Map<String, PackageLicenseResult> results) {
    List<LicenseInfo> allInfos =
        results.values().stream()
            .map(PackageLicenseResult::getEvidence)
            .flatMap(List::stream)
            .toList();
    List<CategoryEnum> categories =
        allInfos.stream()
            .filter(Objects::nonNull)
            .flatMap(
                info ->
                    (info.getIdentifiers() != null ? info.getIdentifiers() : List.<String>of())
                        .stream())
            .map(this::getCategory)
            .filter(Objects::nonNull)
            .toList();
    Map<CategoryEnum, Long> byCategory =
        categories.stream().collect(Collectors.groupingBy(c -> c, Collectors.counting()));

    return new LicensesSummary()
        .total(categories.size())
        .concluded(results.size())
        .permissive(byCategory.getOrDefault(CategoryEnum.PERMISSIVE, 0L).intValue())
        .weakCopyleft(byCategory.getOrDefault(CategoryEnum.WEAK_COPYLEFT, 0L).intValue())
        .strongCopyleft(byCategory.getOrDefault(CategoryEnum.STRONG_COPYLEFT, 0L).intValue())
        .unknown(byCategory.getOrDefault(CategoryEnum.UNKNOWN, 0L).intValue());
  }

  /** The concluded license is the most permissive license in the list. */
  private LicenseInfo getConcluded(List<LicenseInfo> infos) {
    LicenseInfo concluded = null;
    for (var info : infos) {
      if (concluded == null) {
        concluded = info;
      } else {
        if (!isMorePermissive(concluded.getCategory(), info.getCategory())) {
          concluded = info;
        }
      }
    }
    return concluded;
  }
}
