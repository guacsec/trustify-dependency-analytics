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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.camel.Exchange;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.Remediation;
import io.github.guacsec.trustifyda.api.v5.SeverityUtils;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.backend.JsonUtils;
import io.github.guacsec.trustifyda.integration.providers.ProviderResponseHandler;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.github.guacsec.trustifyda.model.trustify.AdvisoryScore;
import io.github.guacsec.trustifyda.model.trustify.ScoreType;
import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@RegisterForReflection
public class TrustifyResponseHandler extends ProviderResponseHandler {

  private static final Logger LOGGER = Logger.getLogger(TrustifyResponseHandler.class);
  private static final String DEFAULT_SOURCE = "manual";

  private static final Map<ScoreType, Integer> SCORE_TYPE_ORDER =
      Map.of(
          ScoreType.V4, 1,
          ScoreType.V3_1, 2,
          ScoreType.V3_0, 3,
          ScoreType.V2, 4);

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
          if (vuln.hasNonNull("withdrawn")) {
            return;
          }
          var status = (ObjectNode) vuln.get("status");
          if (status == null || !status.hasNonNull("affected")) {
            return;
          }
          var affected = (ArrayNode) status.get("affected");
          var id = JsonUtils.getTextValue(vuln, "identifier");
          var title = JsonUtils.getTextValue(vuln, "title");
          final String iTitle;
          if (title == null) {
            iTitle = JsonUtils.getTextValue(vuln, "description");
          } else {
            iTitle = title;
          }
          Map<String, Issue> issuesByCveSource = new HashMap<>();

          affected.forEach(
              data -> {
                if (data.hasNonNull("withdrawn")) {
                  return;
                }
                var source = getSource(data);
                if (source == null) {
                  return;
                }
                var key = String.format("%s:%s", source, id);
                if (issuesByCveSource.containsKey(key)) {
                  return;
                }
                var issue = new Issue().id(id).title(iTitle).source(source).cves(List.of(id));
                setCvssData(issue, data);
                if (issue.getCvssScore() != null) {
                  issuesByCveSource.put(key, issue);
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

  private void setCvssData(Issue issue, JsonNode node) {
    var scores = (ArrayNode) node.get("scores");

    if (scores != null && !scores.isEmpty()) {
      var advisoryScores = getAdvisoryScore(issue.getId(), scores);
      if (!advisoryScores.isEmpty()) {
        var score = advisoryScores.get(0);
        issue.cvssScore(score.score().floatValue());
        if (score.severity() != null) {
          issue.setSeverity(score.severity());
        } else {
          issue.setSeverity(SeverityUtils.fromScore(score.score().floatValue()));
        }
      }
    }
    var ranges = (ArrayNode) node.get("ranges");
    if (ranges == null) {
      return;
    }
    var r = new Remediation();
    ranges.forEach(
        rangeNode -> {
          var events = (ArrayNode) rangeNode.get("events");
          events.forEach(
              eventNode -> {
                var fixed = JsonUtils.getTextValue(eventNode, "fixed");
                if (fixed != null) {
                  r.addFixedInItem(fixed);
                }
              });
        });
    issue.setRemediation(r);
  }

  private List<AdvisoryScore> getAdvisoryScore(String cveId, ArrayNode scores) {
    var result = new ArrayList<AdvisoryScore>();
    scores.forEach(
        score -> {
          try {
            var scoreType = ScoreType.fromValue(JsonUtils.getTextValue(score, "type"));
            var severity = JsonUtils.getTextValue(score, "severity");
            var scoreValue = score.get("value").asDouble();
            result.add(
                new AdvisoryScore(
                    scoreType, SeverityUtils.fromValue(severity.toUpperCase()), scoreValue));
          } catch (IllegalArgumentException e) {
            LOGGER.infof(
                "Unable to parse advisory score: %s for CVE %s: %s",
                score.toString(), cveId, e.getMessage());
          }
        });

    result.sort(
        Comparator.comparing(advisoryScore -> SCORE_TYPE_ORDER.get(advisoryScore.scoreType())));
    return result;
  }

  private String getSource(JsonNode node) {
    var labels = node.get("labels");
    var importer = JsonUtils.getTextValue(labels, "importer");
    if (importer == null || importer.isBlank()) {
      return DEFAULT_SOURCE;
    }
    return importer;
  }
}
