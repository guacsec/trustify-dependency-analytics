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
import org.jboss.logging.Logger;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.ProviderStatus;
import io.github.guacsec.trustifyda.api.v5.Remediation;
import io.github.guacsec.trustifyda.api.v5.RemediationTrustedContent;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;
import io.github.guacsec.trustifyda.model.trustify.Recommendation;
import io.github.guacsec.trustifyda.model.trustify.Vulnerability;

public class RecommendationAggregation implements AggregationStrategy {

  private static final Logger LOGGER = Logger.getLogger(RecommendationAggregation.class);

  @Override
  public Exchange aggregate(Exchange oldExchange, Exchange newExchange) {
    if (oldExchange == null) {
      return newExchange;
    }
    var worstStatus = getWorstStatus(oldExchange, newExchange);

    var providerResponse = getProviderResponse(oldExchange, newExchange);
    if (providerResponse == null) {
      providerResponse = new ProviderResponse(new HashMap<>(), worstStatus);
    }
    Map<PackageRef, IndexedRecommendation> recommendations = null;
    try {
      recommendations = getRecommendations(oldExchange, newExchange);
    } catch (Exception e) {
      LOGGER.warn("Error getting recommendations", e);
    }

    if (providerResponse.pkgItems() == null) {
      providerResponse = new ProviderResponse(new HashMap<>(), worstStatus);
    }
    if (recommendations != null && !recommendations.isEmpty()) {
      setTrustedContent(recommendations, providerResponse);
    }

    oldExchange.getIn().setBody(new ProviderResponse(providerResponse.pkgItems(), worstStatus));
    return oldExchange;
  }

  private ProviderStatus getWorstStatus(Exchange oldExchange, Exchange newExchange) {
    ProviderStatus oldStatus = getStatus(oldExchange);
    ProviderStatus newStatus = getStatus(newExchange);

    if (oldStatus == null && newStatus == null) {
      return null;
    }
    if (oldStatus == null) {
      return newStatus;
    }
    if (newStatus == null) {
      return oldStatus;
    }
    return Boolean.FALSE.equals(oldStatus.getOk()) ? oldStatus : newStatus;
  }

  private ProviderStatus getStatus(Exchange exchange) {
    if (exchange.getIn().getBody() instanceof ProviderResponse response) {
      return response.status();
    }
    return null;
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
                              .status(Vulnerability.Status.toString(vuln.getStatus()))
                              .justification(
                                  Vulnerability.Justification.toString(vuln.getJustification()));
                      issue.remediation(new Remediation().trustedContent(remediation));
                    });
          }
          providerResponse
              .pkgItems()
              .put(
                  key.ref(),
                  new PackageItem(
                      key.ref(),
                      recommendation,
                      issues,
                      pkgItem != null ? pkgItem.warnings() : Collections.emptyList()));
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
