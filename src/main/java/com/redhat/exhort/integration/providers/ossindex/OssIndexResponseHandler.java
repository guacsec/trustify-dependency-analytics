/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.providers.ossindex;

import static com.redhat.exhort.integration.Constants.OSS_INDEX_PROVIDER;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.camel.Body;
import org.apache.camel.ExchangeProperty;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.Issue;
import com.redhat.exhort.api.v4.SeverityUtils;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.ProviderResponseHandler;
import com.redhat.exhort.model.CvssParser;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.ProviderResponse;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@RegisterForReflection
public class OssIndexResponseHandler extends ProviderResponseHandler {

  private static final Logger LOGGER = Logger.getLogger(OssIndexRequestBuilder.class);

  @Inject ObjectMapper mapper;

  @Override
  public ProviderResponse responseToIssues(
      @Body byte[] response,
      @ExchangeProperty(Constants.PROVIDER_PRIVATE_DATA_PROPERTY) String privateProviders,
      @ExchangeProperty(Constants.DEPENDENCY_TREE_PROPERTY) DependencyTree tree)
      throws IOException {
    var json = (ArrayNode) mapper.readTree(response);
    return new ProviderResponse(getIssues(json, tree), null, null);
  }

  private Map<String, List<Issue>> getIssues(ArrayNode response, DependencyTree tree) {
    Map<String, List<Issue>> reports = new HashMap<>();
    Map<String, PackageRef> coordinates =
        tree.getAll().stream()
            .collect(
                Collectors.toMap(
                    d -> new PackageRef(d.toString()).purl().getCoordinates(),
                    d -> d,
                    (a, b) -> a));
    response.forEach(
        n -> {
          var pkgRef = n.get("coordinates").asText();
          try {
            var key = coordinates.get(pkgRef);
            List<Issue> issues = new ArrayList<>();
            var vulnerabilities = (ArrayNode) n.get("vulnerabilities");
            vulnerabilities.forEach(v -> issues.add(toIssue(v)));
            if (!issues.isEmpty()) {
              reports.put(key.ref(), issues);
            }
          } catch (IllegalArgumentException e) {
            LOGGER.warn("Unable to parse PackageURL: " + pkgRef, e);
          }
        });

    return reports;
  }

  private Issue toIssue(JsonNode data) {
    var score = data.get("cvssScore").floatValue();
    return new Issue()
        .id(data.get("id").asText())
        .title(data.get("title").asText())
        .cves(List.of(data.get("cve").asText()))
        .cvss(CvssParser.fromVectorString(data.get("cvssVector").asText()))
        .cvssScore(score)
        .severity(SeverityUtils.fromScore(score))
        .source(OSS_INDEX_PROVIDER);
  }

  @Override
  protected String getProviderName() {
    return OSS_INDEX_PROVIDER;
  }
}
