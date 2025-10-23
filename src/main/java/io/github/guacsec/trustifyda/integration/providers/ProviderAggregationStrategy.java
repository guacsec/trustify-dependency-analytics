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

package io.github.guacsec.trustifyda.integration.providers;

import java.util.HashMap;
import java.util.Map;

import org.apache.camel.Body;
import org.apache.camel.ExchangeProperty;

import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.Scanned;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.trustedcontent.TrustedContentResponse;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class ProviderAggregationStrategy {

  public Map<String, ProviderReport> aggregate(
      Map<String, ProviderReport> aggregated, ProviderReport report) {
    if (aggregated == null) {
      aggregated = new HashMap<>();
    }
    aggregated.put(report.getStatus().getName(), report);
    return aggregated;
  }

  public AnalysisReport toReport(
      @Body Map<String, ProviderReport> reports,
      @ExchangeProperty(Constants.DEPENDENCY_TREE_PROPERTY) DependencyTree tree,
      @ExchangeProperty(Constants.TRUSTED_CONTENT_PROVIDER) TrustedContentResponse tcResponse) {

    reports.put(
        Constants.TRUSTED_CONTENT_PROVIDER, new ProviderReport().status(tcResponse.status()));
    var scanned = new Scanned().direct(tree.directCount()).transitive(tree.transitiveCount());
    scanned.total(scanned.getDirect() + scanned.getTransitive());
    return new AnalysisReport().providers(reports).scanned(scanned);
  }
}
