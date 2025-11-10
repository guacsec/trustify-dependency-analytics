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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.camel.AggregationStrategy;
import org.apache.camel.Exchange;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.Remediation;
import io.github.guacsec.trustifyda.api.v5.RemediationTrustedContent;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;
import io.github.guacsec.trustifyda.model.trustify.Recommendation;

public class RecommendationAggregation implements AggregationStrategy {

  @Override
  public Exchange aggregate(Exchange oldExchange, Exchange newExchange) {
    if (oldExchange == null) {
      return newExchange;
    }
    var providerResponse = getProviderResponse(oldExchange, newExchange);
    var recommendations = getRecommendations(oldExchange, newExchange);

    if (providerResponse.pkgItems() == null) {
      providerResponse = new ProviderResponse(new HashMap<>(), providerResponse.status());
    }
    if (recommendations != null && !recommendations.isEmpty()) {
      setTrustedContent(recommendations, providerResponse);
    }

    oldExchange.getIn().setBody(providerResponse);
    return oldExchange;
  }

  private ProviderResponse getProviderResponse(Exchange oldExchange, Exchange newExchange) {
    var body = oldExchange.getIn().getBody();
    if (body != null && body instanceof ProviderResponse) {
      return (ProviderResponse) body;
    }
    body = newExchange.getIn().getBody();
    if (body != null && body instanceof ProviderResponse) {
      return (ProviderResponse) body;
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private Map<PackageRef, IndexedRecommendation> getRecommendations(
      Exchange oldExchange, Exchange newExchange) {
    var body = oldExchange.getIn().getBody();
    if (body != null && body instanceof Map) {
      return (Map<PackageRef, IndexedRecommendation>) body;
    }
    body = newExchange.getIn().getBody();
    if (body != null && body instanceof Map) {
      return (Map<PackageRef, IndexedRecommendation>) body;
    }
    return null;
  }

  private void setTrustedContent(
      Map<PackageRef, IndexedRecommendation> recommendations, ProviderResponse providerResponse) {
    recommendations.forEach(
        (key, value) -> {
          var pkgItem = providerResponse.pkgItems().get(key.ref());
          var recommendation = toRecommendation(value);
          var issues = new ArrayList<Issue>();
          if (pkgItem != null && pkgItem.issues() != null) {
            issues.addAll(pkgItem.issues());
            pkgItem
                .issues()
                .forEach(
                    issue -> {
                      if (value.vulnerabilities() == null || value.vulnerabilities().isEmpty()) {
                        return;
                      }
                      var vuln = value.vulnerabilities().get(issue.getId());
                      if (vuln == null) {
                        return;
                      }
                      var remediation =
                          new RemediationTrustedContent()
                              .ref(value.packageName())
                              .status(vuln.getStatus())
                              .justification(vuln.getJustification());
                      issue.remediation(new Remediation().trustedContent(remediation));
                    });
          }
          providerResponse
              .pkgItems()
              .put(key.ref(), new PackageItem(key.ref(), recommendation, issues));
        });
  }

  private Recommendation toRecommendation(IndexedRecommendation recommendation) {
    if (recommendation.vulnerabilities() == null) {
      return new Recommendation(recommendation.packageName(), Collections.emptyList());
    }
    return new Recommendation(
        recommendation.packageName(), recommendation.vulnerabilities().values().stream().toList());
  }
}
