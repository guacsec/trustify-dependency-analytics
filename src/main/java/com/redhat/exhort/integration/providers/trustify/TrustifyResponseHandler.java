/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
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

package com.redhat.exhort.integration.providers.trustify;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.camel.Body;
import org.apache.camel.ExchangeProperty;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.Issue;
import com.redhat.exhort.api.v4.Remediation;
import com.redhat.exhort.api.v4.SeverityUtils;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.ProviderResponseHandler;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.ProviderResponse;
import com.redhat.exhort.model.trustify.AdvisoryScore;
import com.redhat.exhort.model.trustify.ScoreType;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@RegisterForReflection
public class TrustifyResponseHandler extends ProviderResponseHandler {

  private static final Map<ScoreType, Integer> SCORE_TYPE_ORDER =
      Map.of(
          ScoreType.V4, 1,
          ScoreType.V3_1, 2,
          ScoreType.V3_0, 3,
          ScoreType.V2, 4);

  @Inject ObjectMapper mapper;

  @Override
  protected String getProviderName() {
    return Constants.TRUSTIFY_PROVIDER;
  }

  @Override
  public ProviderResponse responseToIssues(
      @Body byte[] response,
      @ExchangeProperty(Constants.PROVIDER_PRIVATE_DATA_PROPERTY) String privateProviders,
      @ExchangeProperty(Constants.DEPENDENCY_TREE_PROPERTY) DependencyTree tree)
      throws IOException {
    var json = (ObjectNode) mapper.readTree(response);
    return new ProviderResponse(getIssues(json, tree), null, null);
  }

  private Map<String, List<Issue>> getIssues(ObjectNode response, DependencyTree tree) {
    return tree.getAll().stream()
        .map(PackageRef::ref)
        .filter(ref -> response.has(ref))
        .collect(Collectors.toMap(ref -> ref, ref -> toIssues(ref, (ArrayNode) response.get(ref))));
  }

  private List<Issue> toIssues(String ref, ArrayNode response) {
    if (response.isEmpty()) {
      return Collections.emptyList();
    }
    List<Issue> issues = new ArrayList<>();
    response.forEach(
        vuln -> {
          var status = (ObjectNode) vuln.get("status");
          if (status == null || !status.hasNonNull("affected")) {
            return;
          }
          var affected = (ArrayNode) status.get("affected");
          var id = getTextValue(vuln, "identifier");
          var title = getTextValue(vuln, "title");
          final String iTitle;
          if (title == null) {
            iTitle = getTextValue(vuln, "description");
          } else {
            iTitle = title;
          }
          Map<String, Issue> issuesByCveSource = new HashMap<>();

          affected.forEach(
              data -> {
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

  private void setCvssData(Issue issue, JsonNode node) {
    var scores = (ArrayNode) node.get("scores");

    if (scores != null && !scores.isEmpty()) {
      var advisoryScores = getAdvisoryScore(scores);
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
                var fixed = getTextValue(eventNode, "fixed");
                if (fixed != null) {
                  r.addFixedInItem(fixed);
                }
              });
        });
    issue.setRemediation(r);
  }

  private List<AdvisoryScore> getAdvisoryScore(ArrayNode scores) {
    var result = new ArrayList<AdvisoryScore>();
    scores.forEach(
        score -> {
          var scoreType = ScoreType.fromValue(getTextValue(score, "type"));
          var severity = getTextValue(score, "severity");
          var scoreValue = score.get("value").asDouble();
          result.add(
              new AdvisoryScore(
                  scoreType, SeverityUtils.fromValue(severity.toUpperCase()), scoreValue));
        });

    result.sort(
        Comparator.comparing(advisoryScore -> SCORE_TYPE_ORDER.get(advisoryScore.scoreType())));
    return result;
  }

  private String getTextValue(JsonNode node, String key) {
    if (node.has(key) && node.hasNonNull(key)) {
      return node.get(key).asText();
    }
    return null;
  }

  private String getSource(JsonNode node) {
    var labels = node.get("labels");
    if (labels == null) {
      return null;
    }
    return getTextValue(labels, "type");
  }
}
