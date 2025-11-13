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

package io.github.guacsec.trustifyda.integration.providers.osv;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.camel.Exchange;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.Remediation;
import io.github.guacsec.trustifyda.api.v5.SeverityUtils;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.providers.ProviderResponseHandler;
import io.github.guacsec.trustifyda.model.CvssParser;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import us.springett.cvss.Cvss;

@ApplicationScoped
@RegisterForReflection
public class OsvResponseHandler extends ProviderResponseHandler {

  @Inject ObjectMapper mapper;

  @Override
  protected String getProviderName(Exchange exchange) {
    return Constants.OSV_PROVIDER;
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
                ref -> new PackageItem(ref, null, toIssues((ArrayNode) response.get(ref)))));
  }

  private List<Issue> toIssues(ArrayNode response) {
    if (response.isEmpty()) {
      return Collections.emptyList();
    }
    List<Issue> issues = new ArrayList<>();
    response.forEach(
        data -> {
          var issue = new Issue().source(Constants.OSV_PROVIDER);

          String cve = getTextValue(data, "id");
          if (cve == null) {
            return;
          }
          issue.id(cve).cves(List.of(cve));
          issue.title(getTextValue(data, "summary"));
          if (issue.getTitle() == null || issue.getTitle().isEmpty()) {
            issue.title(getTextValue(data, "description"));
          }
          var severity = data.get("severity");
          if (severity != null) {
            setSeverity(severity, issue);
          }
          var affected = data.get("affected");
          if (affected != null) {
            issue.setRemediation(getRemediation((ArrayNode) affected));
          }
          if (issue.getCvssScore() != null) {
            issues.add(issue);
          }
        });
    return issues;
  }

  // Prefer V3.1 and V3.0 over V2 CVSS vectors
  private void setSeverity(JsonNode severity, Issue issue) {
    Map<String, String> severities = new HashMap<>();

    severity.forEach(
        metricNode -> {
          var vector = metricNode.get("score").asText();
          var type = metricNode.get("type").asText();
          severities.put(type, vector);
        });
    var cvss = severities.get("CVSS_V3");
    if (cvss != null) {
      setCvssData(issue, cvss);
    } else {
      cvss = severities.get("CVSS_V2");
      if (cvss != null) {
        setCvssData(issue, cvss);
      }
    }
  }

  private void setCvssData(Issue issue, String vector) {
    if (issue.getCvss() != null) {
      return;
    }
    var cvss = Cvss.fromVector(vector);
    var score = Double.valueOf(cvss.calculateScore().getBaseScore()).floatValue();
    issue
        .cvssScore(score)
        .cvss(CvssParser.fromVectorString(vector))
        .severity(SeverityUtils.fromScore(score));
  }

  private Remediation getRemediation(ArrayNode affected) {
    var r = new Remediation();
    affected.forEach(
        affectedNode -> {
          var ranges = (ArrayNode) affectedNode.get("ranges");
          if (ranges == null) {
            return;
          }
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
        });
    return r;
  }

  private String getTextValue(JsonNode node, String key) {
    if (node.has(key)) {
      return node.get(key).asText();
    }
    return null;
  }
}
