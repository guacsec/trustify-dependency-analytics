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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

import org.apache.camel.Body;
import org.apache.camel.ExchangeProperty;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.LicenseInfoFactory;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.expandedlicensing.ConjunctiveLicenseSet;
import org.spdx.library.model.v3_0_1.expandedlicensing.DisjunctiveLicenseSet;
import org.spdx.library.model.v3_0_1.expandedlicensing.ListedLicense;
import org.spdx.library.model.v3_0_1.expandedlicensing.ListedLicenseException;
import org.spdx.library.model.v3_0_1.expandedlicensing.WithAdditionOperator;
import org.spdx.library.model.v3_0_1.simplelicensing.AnyLicenseInfo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import io.github.guacsec.trustifyda.api.v5.LicenseCategory;
import io.github.guacsec.trustifyda.api.v5.LicenseIdentifier;
import io.github.guacsec.trustifyda.api.v5.LicenseInfo;
import io.github.guacsec.trustifyda.api.v5.LicenseProviderResult;
import io.github.guacsec.trustifyda.api.v5.PackageLicenseResult;
import io.github.guacsec.trustifyda.api.v5.ProviderStatus;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.licenses.LicenseConfig;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.runtime.util.HashUtil;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;

@ApplicationScoped
public class SpdxLicenseService {

  private static final Logger LOGGER = Logger.getLogger(SpdxLicenseService.class);
  private static final String SBOM_SOURCE = "SBOM";
  private static final String SPDX_SOURCE = "SPDX";
  private static final String SPDX_SOURCE_URL = "https://spdx.org";

  /**
   * Deprecated SPDX license ids that are replaced by "license WITH exception" form. Normalizing
   * before parse so we get canonical id/name and WITH in the expression.
   */
  private static final Map<String, String> DEPRECATED_TO_CANONICAL =
      Map.of(
          "GPL-2.0-with-classpath-exception", "GPL-2.0-only WITH Classpath-exception-2.0",
          "GPL-2.0-with-classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0");

  @ConfigProperty(name = "categories.file", defaultValue = "license-categories.yaml")
  String categoriesFile;

  private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

  /**
   * Header hash (first 5 lines normalized) -> SPDX license id. Built lazily from SPDX library on
   * first identifyLicense call (library may download license list on first use).
   */
  private final Map<String, String> headerHashToLicenseId = new HashMap<>();

  @Inject ExecutorService executorService;
  @Inject ObjectMapper mapper;

  private LicenseConfig licenseConfig;

  void onStart(@Observes StartupEvent ev) {
    SpdxModelFactory.init();
    var loadHeadersFuture = CompletableFuture.runAsync(this::loadHeaders, executorService);
    var loadCategoriesFuture = CompletableFuture.runAsync(this::loadCategories, executorService);
    CompletableFuture.allOf(loadHeadersFuture, loadCategoriesFuture).join();
  }

  private void loadHeaders() {
    try {
      List<String> ids = LicenseInfoFactory.getSpdxListedLicenseIds();
      if (ids != null) {
        for (String licenseId : ids) {
          LOGGER.debugf("Loading header for license %s", licenseId);
          try (var stream =
              getClass()
                  .getClassLoader()
                  .getResourceAsStream("spdx-licenses/" + licenseId + ".json")) {
            if (stream == null) {
              LOGGER.warnf("License file not found: %s", licenseId);
              continue;
            }
            var json = mapper.readTree(stream);
            var licenseText = json.get("licenseText").asText();
            var header = extractHeader(licenseText);
            headerHashToLicenseId.put(HashUtil.sha256(header), licenseId);
          } catch (IOException e) {
            LOGGER.debugf("Could not load header for license %s: %s", licenseId, e.getMessage());
          }
        }
      }
      LOGGER.infof("Built SPDX header map with %d entries", headerHashToLicenseId.size());
    } catch (Exception e) {
      LOGGER.error("Error building SPDX header map", e);
    }
  }

  private void loadCategories() {
    try (var file = getClass().getClassLoader().getResourceAsStream(categoriesFile)) {
      if (file != null) {
        licenseConfig = YAML_MAPPER.readValue(file, LicenseConfig.class);
      } else {
        LOGGER.info("Licenses config not found on classpath: " + categoriesFile);
        licenseConfig = YAML_MAPPER.readValue(new File(categoriesFile), LicenseConfig.class);
      }
    } catch (IOException ex) {
      LOGGER.error("Error loading licenses file", ex);
    }
    if (licenseConfig == null) {
      throw new RuntimeException("Licenses config not found on classpath: " + categoriesFile);
    }
  }

  public LicenseIdentifier identifyLicense(String licenseFile) {
    String header = extractHeader(licenseFile);
    if (header == null) {
      throw new NotFoundException("License header not found in license file");
    }
    String licenseId = headerHashToLicenseId.get(HashUtil.sha256(header));
    if (licenseId == null) {
      throw new NotFoundException("License not found with header: " + header);
    }
    try {
      ListedLicense license = LicenseInfoFactory.getListedLicenseById(licenseId);
      if (license == null) {
        throw new NotFoundException("License not found with ID: " + licenseId);
      }
      return toLicenseIdentifier(license, null, licenseId);
    } catch (InvalidSPDXAnalysisException e) {
      throw new NotFoundException("License not found with ID: " + licenseId, e);
    }
  }

  public LicenseInfo fromLicenseId(String expression, String sourceId, String sourceUrl) {
    if (expression == null || expression.isBlank()) {
      throw new NotFoundException("License expression is required");
    }
    String trimmed = expression.trim();
    // Use canonical form when input is exactly a deprecated "license-with-exception" id
    String toParse = DEPRECATED_TO_CANONICAL.getOrDefault(trimmed, trimmed);
    AnyLicenseInfo root;
    try {
      root = LicenseInfoFactory.parseSPDXLicenseString(toParse);
    } catch (InvalidSPDXAnalysisException e) {
      if (!trimmed.contains(" AND ") && !trimmed.contains(" OR ") && !trimmed.contains(" WITH ")) {
        LicenseCategory category = LicenseCategory.UNKNOWN;
        return new LicenseInfo()
            .identifiers(List.of(toUnknownLicenseIdentifier(trimmed)))
            .category(category)
            .name(trimmed)
            .source(sourceId == null ? SPDX_SOURCE : sourceId)
            .sourceUrl(sourceUrl == null ? SPDX_SOURCE_URL : sourceUrl)
            .expression(trimmed);
      }
      throw new NotFoundException("Invalid license expression: " + expression, e);
    }
    String normalizedExpression = root.toString();
    String humanReadableName = toHumanReadableName(root);
    List<LicenseIdentifier> identifiers;
    try {
      identifiers = parseExpressionToIdentifiers(normalizedExpression);
    } catch (InvalidSPDXAnalysisException e) {
      throw new NotFoundException("Invalid license expression: " + expression, e);
    }
    if (identifiers.isEmpty()) {
      throw new NotFoundException("License category not found for expression: " + expression);
    }
    boolean isOr = normalizedExpression.contains(" OR ");
    LicenseCategory category = resolveCategoryFromIdentifiers(identifiers, isOr);
    if (category == null) {
      throw new NotFoundException("License category not found for expression: " + expression);
    }
    return new LicenseInfo()
        .identifiers(identifiers)
        .category(category)
        .name(humanReadableName)
        .source(sourceId == null ? SPDX_SOURCE : sourceId)
        .sourceUrl(sourceUrl == null ? SPDX_SOURCE_URL : sourceUrl)
        .expression(normalizedExpression);
  }

  /** Returns true if category1 is more permissive than category2. */
  public boolean isMorePermissive(LicenseCategory category1, LicenseCategory category2) {
    if (category1 == category2) {
      return false;
    }
    return getCategoryRank(category1) > getCategoryRank(category2);
  }

  public List<LicenseProviderResult> aggregateSbomLicenses(
      @Body LicenseProviderResult depsDevResult,
      @ExchangeProperty(Constants.DEPENDENCY_TREE_PROPERTY) DependencyTree dependencyTree) {
    if (dependencyTree == null
        || dependencyTree.licenseExpressions() == null
        || dependencyTree.licenseExpressions().isEmpty()) {
      return List.of(depsDevResult);
    }
    var sbomPackages = new HashMap<String, PackageLicenseResult>();
    LicenseInfo projectLicense = null;
    for (var entry : dependencyTree.licenseExpressions().entrySet()) {
      var license = fromLicenseId(entry.getValue(), SBOM_SOURCE, null);
      if (!entry.getKey().equals(dependencyTree.root().ref())) {
        sbomPackages.put(
            entry.getKey(),
            new PackageLicenseResult()
                .evidence(List.of(license))
                .concluded(getConcluded(List.of(license))));
      } else {
        projectLicense = license;
      }
    }

    var sbomResult =
        new LicenseProviderResult()
            .packages(sbomPackages)
            .projectLicense(projectLicense)
            .summary(LicenseSummaryUtils.buildSummary(sbomPackages))
            .status(new ProviderStatus().ok(true).name(SBOM_SOURCE).message("OK").code(200));

    return List.of(sbomResult, depsDevResult);
  }

  /** The concluded license is the most permissive license in the list. */
  public LicenseInfo getConcluded(List<LicenseInfo> infos) {
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

  private List<LicenseIdentifier> parseExpressionToIdentifiers(String expression)
      throws InvalidSPDXAnalysisException {
    AnyLicenseInfo root = LicenseInfoFactory.parseSPDXLicenseString(expression.trim());
    List<LicenseIdentifier> out = new ArrayList<>();
    collectIdentifiers(root, out);
    return out;
  }

  /**
   * Builds a human-readable name for the expression (e.g. "GNU GPL v2.0 only with Classpath
   * exception 2.0"). Used as evidence/display name.
   */
  private String toHumanReadableName(AnyLicenseInfo node) {
    try {
      if (node instanceof ConjunctiveLicenseSet set) {
        var members = set.getMembers();
        return members != null
            ? members.stream()
                .map(this::toHumanReadableName)
                .reduce((a, b) -> a + " AND " + b)
                .orElse(node.toString())
            : node.toString();
      }
      if (node instanceof DisjunctiveLicenseSet set) {
        var members = set.getMembers();
        return members != null
            ? members.stream()
                .map(this::toHumanReadableName)
                .reduce((a, b) -> a + " OR " + b)
                .orElse(node.toString())
            : node.toString();
      }
      if (node instanceof WithAdditionOperator with) {
        var subject = with.getSubjectExtendableLicense();
        if (subject == null) {
          return node.toString();
        }
        String subjectName = toHumanReadableName(subject);
        var addition = with.getSubjectAddition();
        if (addition instanceof ListedLicenseException ex) {
          String exName = ex.getName().orElse(ex.toString());
          return subjectName + " with " + exName;
        }
        return subjectName;
      }
      if (node instanceof ListedLicense license) {
        return license.getName().orElse(license.toString());
      }
      return node.toString();
    } catch (InvalidSPDXAnalysisException e) {
      return node.toString();
    }
  }

  private void collectIdentifiers(AnyLicenseInfo node, List<LicenseIdentifier> out)
      throws InvalidSPDXAnalysisException {
    if (node instanceof ConjunctiveLicenseSet set) {
      for (AnyLicenseInfo member : set.getMembers()) {
        collectIdentifiers(member, out);
      }
      return;
    }
    if (node instanceof DisjunctiveLicenseSet set) {
      for (AnyLicenseInfo member : set.getMembers()) {
        collectIdentifiers(member, out);
      }
      return;
    }
    if (node instanceof WithAdditionOperator with) {
      var subject = with.getSubjectExtendableLicense();
      var addition = with.getSubjectAddition();
      ListedLicense license = subject instanceof ListedLicense ? (ListedLicense) subject : null;
      ListedLicenseException exception =
          addition instanceof ListedLicenseException ? (ListedLicenseException) addition : null;
      if (license != null) {
        String expressionForCategory =
            license.toString() + " WITH " + (exception != null ? exception.toString() : "");
        out.add(toLicenseIdentifier(license, exception, expressionForCategory));
      } else {
        out.add(toUnknownLicenseIdentifier(with.toString()));
      }
      return;
    }
    if (node instanceof ListedLicense license) {
      out.add(toLicenseIdentifier(license, null, license.toString()));
      return;
    }
    out.add(toUnknownLicenseIdentifier(node.toString()));
  }

  private LicenseCategory resolveCategoryFromIdentifiers(
      List<LicenseIdentifier> identifiers, boolean isOrExpression) {
    LicenseCategory category = null;
    for (LicenseIdentifier id : identifiers) {
      LicenseCategory next = id.getCategory();
      if (category == null) {
        category = next;
      } else {
        if (isOrExpression) {
          if (isMorePermissive(next, category)) {
            category = next;
          }
        } else {
          if (isMorePermissive(category, next)) {
            category = next;
          }
        }
      }
    }
    return category;
  }

  private String extractHeader(String licenseText) {
    if (licenseText == null || licenseText.isBlank()) {
      return null;
    }
    String normalized = licenseText.replace("\r\n", "\n").replace('\r', '\n');
    String[] headerLines;
    if (!normalized.contains("\n\n")) {
      headerLines = normalized.split("\n");
    } else {
      headerLines = normalized.substring(0, normalized.indexOf("\n\n")).split("\n");
    }
    var header = new StringBuilder();
    for (int i = 0; i < headerLines.length && i < 5; i++) {
      header.append(headerLines[i].strip()).append("\n");
    }
    return header.toString().strip();
  }

  private LicenseCategory getCategory(String licenseExpression) {
    String baseLicense = licenseExpression;
    final String exceptionSuffix;
    if (licenseExpression.contains(" WITH ")) {
      int i = licenseExpression.indexOf(" WITH ");
      baseLicense = licenseExpression.substring(0, i).trim();
      exceptionSuffix = licenseExpression.substring(i + " WITH ".length()).trim();
    } else if (licenseExpression.contains("-with-")) {
      int i = licenseExpression.indexOf("-with-");
      baseLicense = licenseExpression.substring(0, i);
      exceptionSuffix = licenseExpression.substring(i + "-with-".length());
    } else {
      exceptionSuffix = null;
    }
    if (baseLicense.endsWith("-only")) {
      baseLicense = baseLicense.substring(0, baseLicense.length() - "-only".length());
    }
    if (baseLicense.endsWith("-or-later")) {
      baseLicense = baseLicense.substring(0, baseLicense.length() - "-or-later".length());
    }
    if (licenseConfig.permissive().contains(baseLicense)) {
      return LicenseCategory.PERMISSIVE;
    }
    if (licenseConfig.weakCopyleft().contains(baseLicense)) {
      return LicenseCategory.WEAK_COPYLEFT;
    }
    if (licenseConfig.strongCopyleft().contains(baseLicense)) {
      if (exceptionSuffix != null
          && licenseConfig.weakCopyleftExceptions() != null
          && licenseConfig.weakCopyleftExceptions().stream()
              .anyMatch(e -> e.equalsIgnoreCase(exceptionSuffix))) {
        return LicenseCategory.WEAK_COPYLEFT;
      }
      return LicenseCategory.STRONG_COPYLEFT;
    }
    return LicenseCategory.UNKNOWN;
  }

  private int getCategoryRank(LicenseCategory category) {
    if (category == null) {
      return -1;
    }
    return switch (category) {
      case PERMISSIVE -> 4;
      case WEAK_COPYLEFT -> 3;
      case STRONG_COPYLEFT -> 2;
      case UNKNOWN -> 1;
      default -> 0;
    };
  }

  /**
   * Normalized id (e.g. GPL-2.0-only or GPL-2.0-only WITH Classpath-exception-2.0), human-readable
   * name including exception when present; exception field not set on identifier.
   */
  private LicenseIdentifier toLicenseIdentifier(
      ListedLicense license, ListedLicenseException exception, String expressionForCategory)
      throws InvalidSPDXAnalysisException {
    String licenseId = license.toString();
    String id = exception != null ? licenseId + " WITH " + exception.toString() : licenseId;
    String licenseName = license.getName().orElse(licenseId);
    String name =
        exception != null
            ? licenseName + " with " + exception.getName().orElse(exception.toString())
            : licenseName;
    Boolean osi = license.getIsOsiApproved().orElse(null);
    Boolean fsf = license.getIsFsfLibre().orElse(null);
    Boolean deprecated = license.getIsDeprecatedLicenseId().orElse(null);
    LicenseCategory category =
        getCategory(expressionForCategory != null ? expressionForCategory : id);
    return new LicenseIdentifier()
        .id(id)
        .name(name)
        .isOsiApproved(osi)
        .isFsfLibre(fsf)
        .isDeprecated(deprecated)
        .category(category);
  }

  private LicenseIdentifier toUnknownLicenseIdentifier(String licenseId) {
    return new LicenseIdentifier().id(licenseId).name(licenseId).category(LicenseCategory.UNKNOWN);
  }
}
