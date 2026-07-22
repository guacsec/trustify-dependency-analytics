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

package io.github.guacsec.trustifyda.integration.providers.trustify;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.camel.Exchange;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AdvisoryInfo;
import io.github.guacsec.trustifyda.api.v5.AdvisoryRemediation;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.Remediation;
import io.github.guacsec.trustifyda.api.v5.RemediationCategory;
import io.github.guacsec.trustifyda.api.v5.RemediationInfo;
import io.github.guacsec.trustifyda.api.v5.SeverityUtils;
import io.github.guacsec.trustifyda.api.v5.VersionRange;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.backend.JsonUtils;
import io.github.guacsec.trustifyda.integration.providers.ProviderResponseHandler;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@RegisterForReflection
public class TrustifyResponseHandler extends ProviderResponseHandler {

  private static final Logger LOGGER = Logger.getLogger(TrustifyResponseHandler.class);
  private static final String DEFAULT_SOURCE = "manual";

  @Inject ObjectMapper mapper;

  @Override
  protected String getProviderName(Exchange exchange) {
    return exchange.getProperty(Constants.PROVIDER_NAME_PROPERTY, String.class);
  }

  @Override
  public ProviderResponse responseToIssues(Exchange exchange) throws IOException {
    var response = exchange.getIn().getBody(byte[].class);
    var tree = exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class);
    var json = (ObjectNode) mapper.readTree(response);
    return new ProviderResponse(getIssues(json, tree), defaultOkStatus(getProviderName(exchange)));
  }

  private Map<String, PackageItem> getIssues(ObjectNode response, DependencyTree tree) {
    return tree.getAll().stream()
        .map(PackageRef::ref)
        .filter(ref -> response.has(ref))
        .collect(
            Collectors.toMap(
                ref -> ref,
                ref ->
                    new PackageItem(
                        ref, null, toIssues(response.get(ref)), getWarnings(response.get(ref)))));
  }

  private List<Issue> toIssues(JsonNode response) {
    if (response.isEmpty()) {
      return Collections.emptyList();
    }
    ArrayNode details = (ArrayNode) response.get("details");
    if (details == null) {
      details = (ArrayNode) response;
    }
    if (details.isEmpty()) {
      return Collections.emptyList();
    }

    List<Issue> issues = new ArrayList<>();
    details.forEach(
        vuln -> {
          var id = JsonUtils.getTextValue(vuln, "identifier");
          if (vuln.hasNonNull("withdrawn")) {
            return;
          }

          var purlStatuses = (ArrayNode) vuln.get("purl_statuses");
          if (purlStatuses == null || purlStatuses.isEmpty()) {
            return;
          }
          var title = JsonUtils.getTextValue(vuln, "title");
          final String iTitle;
          if (title == null) {
            iTitle = JsonUtils.getTextValue(vuln, "description");
          } else {
            iTitle = title;
          }

          Map<String, Issue> issuesByCveSource = new HashMap<>();

          purlStatuses.forEach(
              purlStatus -> {
                var advisory = purlStatus.get("advisory");
                if (advisory != null && advisory.hasNonNull("withdrawn")) {
                  return;
                }
                var source = getSource(purlStatus);
                if (source == null) {
                  return;
                }
                var key = String.format("%s:%s", source, id);
                if (issuesByCveSource.containsKey(key)) {
                  mergeIssueData(issuesByCveSource.get(key), vuln, purlStatus);
                  return;
                }
                var issue = new Issue().id(id).title(iTitle).source(source).cves(List.of(id));
                setCvssData(issue, vuln, purlStatus);
                issuesByCveSource.put(key, issue);
              });
          issuesByCveSource
              .values()
              .forEach(
                  issue -> {
                    var remediation = issue.getRemediation();
                    if (remediation != null && remediation.getFixedIn() != null) {
                      remediation.getFixedIn().sort(VersionComparator.INSTANCE);
                    }
                  });
          issues.addAll(issuesByCveSource.values());
        });

    return issues;
  }

  private List<String> getWarnings(JsonNode entryValue) {
    var values = entryValue.get("warnings");
    if (values == null || !values.isArray()) {
      return Collections.emptyList();
    }
    List<String> warnings = new ArrayList<>();
    ((ArrayNode) values)
        .forEach(
            warning -> {
              warnings.add(warning.asText());
            });
    return warnings;
  }

  private void setCvssData(Issue issue, JsonNode vuln, JsonNode purlStatus) {
    var sd = extractScoreData(vuln, purlStatus);

    if (sd.score != null) {
      issue.cvssScore(sd.score);
    }
    if (sd.severity != null) {
      try {
        issue.setSeverity(SeverityUtils.fromValue(sd.severity.toUpperCase()));
      } catch (IllegalArgumentException e) {
        LOGGER.infof(
            "Unknown severity value: %s, falling back to score-based severity", sd.severity);
        if (sd.score != null) {
          issue.setSeverity(SeverityUtils.fromScore(sd.score));
        }
      }
    } else if (sd.score != null) {
      issue.setSeverity(SeverityUtils.fromScore(sd.score));
    }

    var advRem = createAdvisoryRemediation(purlStatus);
    if (advRem != null) {
      var r = new Remediation();
      r.addAdvisoriesItem(advRem);
      if (advRem.getFixedIn() != null) {
        r.addFixedInItem(advRem.getFixedIn());
      }
      issue.setRemediation(r);
    }
  }

  private void mergeIssueData(Issue existing, JsonNode vuln, JsonNode purlStatus) {
    var sd = extractScoreData(vuln, purlStatus);

    if (sd.score != null
        && (existing.getCvssScore() == null || sd.score > existing.getCvssScore())) {
      existing.cvssScore(sd.score);
      if (sd.severity != null) {
        try {
          existing.setSeverity(SeverityUtils.fromValue(sd.severity.toUpperCase()));
        } catch (IllegalArgumentException e) {
          existing.setSeverity(SeverityUtils.fromScore(sd.score));
        }
      } else {
        existing.setSeverity(SeverityUtils.fromScore(sd.score));
      }
    }

    var advRem = createAdvisoryRemediation(purlStatus);
    if (advRem != null) {
      var r = ensureRemediation(existing);
      mergeAdvisoryRemediation(r, advRem);
    }
  }

  private record ScoreData(Float score, String severity) {}

  private ScoreData extractScoreData(JsonNode vuln, JsonNode purlStatus) {
    Float score = null;
    String severity = null;

    var baseScore = vuln.get("base_score");
    if (baseScore != null && !baseScore.isNull()) {
      score = baseScore.has("score") ? (float) baseScore.get("score").asDouble() : null;
      severity = JsonUtils.getTextValue(baseScore, "severity");
    }

    if (score == null) {
      var scores = purlStatus.get("scores");
      if (scores != null && scores.isArray() && !scores.isEmpty()) {
        for (var entry : scores) {
          var entryValue = entry.has("value") ? (float) entry.get("value").asDouble() : null;
          if (entryValue != null && (score == null || entryValue > score)) {
            score = entryValue;
            severity = JsonUtils.getTextValue(entry, "severity");
          }
        }
      }
    }

    return new ScoreData(score, severity);
  }

  private AdvisoryRemediation createAdvisoryRemediation(JsonNode purlStatus) {
    var advisoryInfo = buildAdvisoryInfo(purlStatus);
    var advRem = new AdvisoryRemediation();
    advRem.setAdvisory(advisoryInfo);

    var status = JsonUtils.getTextValue(purlStatus, "status");
    if (status != null) {
      advRem.setStatus(status);
    }

    var versionRange = purlStatus.get("version_range");
    if (versionRange != null && !versionRange.isNull()) {
      advRem.addVersionRangesItem(buildVersionRange(versionRange));
      var highVersion = JsonUtils.getTextValue(versionRange, "high_version");
      var highInclusive = JsonUtils.getBooleanValue(versionRange, "high_inclusive");
      if (highVersion != null && (highInclusive == null || !highInclusive)) {
        advRem.setFixedIn(highVersion);
      }
    }

    var remediations = (ArrayNode) purlStatus.get("remediations");
    if (remediations != null && !remediations.isEmpty()) {
      remediations.forEach(
          rem -> {
            var info = buildRemediationInfoFromNode(rem, advisoryInfo);
            if (info != null) {
              advRem.addRemediationsItem(info);
            }
          });
    } else if (advisoryInfo != null) {
      var info = new RemediationInfo();
      if (advRem.getFixedIn() != null) {
        info.category(RemediationCategory.VENDOR_FIX);
      }
      advRem.addRemediationsItem(info);
    }

    if (advRem.getVersionRanges() != null
        || advRem.getRemediations() != null
        || advRem.getAdvisory() != null) {
      return advRem;
    }
    return null;
  }

  private void mergeAdvisoryRemediation(Remediation r, AdvisoryRemediation advRem) {
    var existingAdvisories = r.getAdvisories();
    if (existingAdvisories != null && advRem.getAdvisory() != null) {
      var existingMatch =
          existingAdvisories.stream()
              .filter(
                  a ->
                      a.getAdvisory() != null
                          && Objects.equals(a.getAdvisory().getId(), advRem.getAdvisory().getId()))
              .findFirst();
      if (existingMatch.isPresent()) {
        var existing = existingMatch.get();
        if (advRem.getVersionRanges() != null) {
          for (var vr : advRem.getVersionRanges()) {
            if (!isDuplicateVersionRange(existing, vr)) {
              existing.addVersionRangesItem(vr);
            }
          }
        }
        if (advRem.getRemediations() != null) {
          for (var rem : advRem.getRemediations()) {
            if (!isDuplicateRemediationInfo(existing.getRemediations(), rem)) {
              existing.addRemediationsItem(rem);
            }
          }
        }
        if (existing.getFixedIn() == null && advRem.getFixedIn() != null) {
          existing.setFixedIn(advRem.getFixedIn());
        }
        if (advRem.getFixedIn() != null) {
          var fixedIn = r.getFixedIn();
          if (fixedIn == null || !fixedIn.contains(advRem.getFixedIn())) {
            r.addFixedInItem(advRem.getFixedIn());
          }
        }
        return;
      }
    }
    r.addAdvisoriesItem(advRem);
    if (advRem.getFixedIn() != null) {
      var fixedIn = r.getFixedIn();
      if (fixedIn == null || !fixedIn.contains(advRem.getFixedIn())) {
        r.addFixedInItem(advRem.getFixedIn());
      }
    }
  }

  private VersionRange buildVersionRange(JsonNode versionRange) {
    var vr = new VersionRange();
    var schemeId = JsonUtils.getTextValue(versionRange, "version_scheme_id");
    if (schemeId != null) {
      vr.versionSchemeId(schemeId);
    }
    var lowVersion = JsonUtils.getTextValue(versionRange, "low_version");
    if (lowVersion != null) {
      vr.lowVersion(lowVersion);
    }
    var lowInclusive = JsonUtils.getBooleanValue(versionRange, "low_inclusive");
    if (lowInclusive != null) {
      vr.lowInclusive(lowInclusive);
    }
    var highVersion = JsonUtils.getTextValue(versionRange, "high_version");
    if (highVersion != null) {
      vr.highVersion(highVersion);
    }
    var highInclusive = JsonUtils.getBooleanValue(versionRange, "high_inclusive");
    if (highInclusive != null) {
      vr.highInclusive(highInclusive);
    }
    return vr;
  }

  private RemediationInfo buildRemediationInfoFromNode(JsonNode rem, AdvisoryInfo advisoryInfo) {
    var info = new RemediationInfo();
    var category = JsonUtils.getTextValue(rem, "category");
    if (category != null) {
      try {
        info.category(RemediationCategory.fromValue(category.toUpperCase()));
      } catch (IllegalArgumentException e) {
        LOGGER.infof("Unknown remediation category: %s", category);
      }
    }
    var details = JsonUtils.getTextValue(rem, "details");
    if (details != null) {
      info.details(details);
    }
    var url = JsonUtils.getTextValue(rem, "url");
    if (url != null) {
      try {
        info.url(URI.create(url));
      } catch (IllegalArgumentException e) {
        LOGGER.infof("Invalid remediation URL: %s", url);
      }
    }
    return info;
  }

  private boolean isDuplicateVersionRange(AdvisoryRemediation advRem, VersionRange vr) {
    var existing = advRem.getVersionRanges();
    if (existing == null) {
      return false;
    }
    return existing.stream()
        .anyMatch(
            e ->
                Objects.equals(e.getLowVersion(), vr.getLowVersion())
                    && Objects.equals(e.getHighVersion(), vr.getHighVersion())
                    && Objects.equals(e.getLowInclusive(), vr.getLowInclusive())
                    && Objects.equals(e.getHighInclusive(), vr.getHighInclusive())
                    && Objects.equals(e.getVersionSchemeId(), vr.getVersionSchemeId()));
  }

  private boolean isDuplicateRemediationInfo(List<RemediationInfo> existing, RemediationInfo info) {
    if (existing == null) {
      return false;
    }
    return existing.stream()
        .anyMatch(
            e ->
                Objects.equals(e.getCategory(), info.getCategory())
                    && Objects.equals(e.getDetails(), info.getDetails())
                    && Objects.equals(e.getUrl(), info.getUrl()));
  }

  private Remediation ensureRemediation(Issue issue) {
    var r = issue.getRemediation();
    if (r == null) {
      r = new Remediation();
      issue.setRemediation(r);
    }
    return r;
  }

  private AdvisoryInfo buildAdvisoryInfo(JsonNode purlStatus) {
    var advisory = purlStatus.get("advisory");
    if (advisory == null) {
      return null;
    }
    var documentId = JsonUtils.getTextValue(advisory, "document_id");
    if (documentId == null) {
      return null;
    }
    var info = new AdvisoryInfo().id(documentId);
    var title = JsonUtils.getTextValue(advisory, "title");
    if (title != null) {
      info.title(title);
    }
    var identifier = JsonUtils.getTextValue(advisory, "identifier");
    if (identifier != null && identifier.startsWith("http")) {
      try {
        info.url(URI.create(identifier));
      } catch (IllegalArgumentException e) {
        LOGGER.infof("Invalid advisory URL: %s", identifier);
      }
    } else if (identifier != null && identifier.startsWith("GHSA-")) {
      info.url(URI.create("https://github.com/advisories/" + identifier));
    } else if (documentId.startsWith("GHSA-")) {
      info.url(URI.create("https://github.com/advisories/" + documentId));
    }
    return info;
  }

  private String getSource(JsonNode purlStatus) {
    var advisory = purlStatus.get("advisory");
    if (advisory == null) {
      return DEFAULT_SOURCE;
    }
    var labels = advisory.get("labels");
    if (labels != null && !labels.isNull()) {
      var importer = JsonUtils.getTextValue(labels, "importer");
      if (importer != null && !importer.isBlank()) {
        return importer;
      }
    }
    var issuer = advisory.get("issuer");
    if (issuer != null && !issuer.isNull()) {
      var name = JsonUtils.getTextValue(issuer, "name");
      if (name != null && !name.isBlank()) {
        return name;
      }
    }
    return DEFAULT_SOURCE;
  }
}
