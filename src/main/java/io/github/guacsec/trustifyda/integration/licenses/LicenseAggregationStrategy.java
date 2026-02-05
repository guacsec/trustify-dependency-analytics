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

import java.util.List;

import org.apache.camel.AggregationStrategy;
import org.apache.camel.Exchange;

import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.LicenseProviderResult;

public class LicenseAggregationStrategy implements AggregationStrategy {
  @Override
  public Exchange aggregate(Exchange oldExchange, Exchange newExchange) {

    if (oldExchange == null) {
      return newExchange;
    }

    Object oldBody = oldExchange.getIn().getBody();
    Object newBody = newExchange.getIn().getBody();

    AnalysisReport vuln = null;
    List<LicenseProviderResult> lic = null;

    switch (oldBody) {
      case AnalysisReport report -> vuln = report;
      case List<?> list -> lic = castToLicenseProviderResultList(list);
      default -> {}
    }

    switch (newBody) {
      case AnalysisReport report -> vuln = report;
      case List<?> list -> lic = castToLicenseProviderResultList(list);
      default -> {}
    }

    if (vuln != null && lic != null) {
      vuln.setLicenses(lic);
      oldExchange.getIn().setBody(vuln);
    }

    return oldExchange;
  }

  @SuppressWarnings("unchecked")
  private static List<LicenseProviderResult> castToLicenseProviderResultList(List<?> list) {
    return (List<LicenseProviderResult>) list;
  }
}
