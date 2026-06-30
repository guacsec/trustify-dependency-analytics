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

package io.github.guacsec.trustifyda.integration.registry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.DependencyReport;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.RecommendationReport;
import io.github.guacsec.trustifyda.api.v5.RecommendationSource;
import io.github.guacsec.trustifyda.api.v5.RecommendationSummary;
import io.github.guacsec.trustifyda.api.v5.Remediation;
import io.github.guacsec.trustifyda.api.v5.RemediationTrustedContent;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.api.v5.SourceSummary;
import io.github.guacsec.trustifyda.model.DependencyTree;

class RegistryEnrichmentService {

  private static final String HASH_ALG_SHA256 = "SHA-256";
  private static final String TRUSTED_LIBRARIES_SOURCE = "trusted-libraries";

  void enrichReport(
      AnalysisReport report,
      DependencyTree tree,
      String packagePrefix,
      BiFunction<String, String, Optional<PackageRef>> registryQuery) {
    var providers = report.getProviders();
    if (providers == null || providers.isEmpty()) {
      return;
    }

    Map<String, Map<String, String>> hashes = tree.componentHashes();
    Set<String> processedPurls =
        enrichExistingDependencies(providers, hashes, packagePrefix, registryQuery);
    enrichUnreportedDependencies(
        providers, tree, hashes, packagePrefix, registryQuery, processedPurls);
    recountRecommendations(providers);
  }

  private Set<String> enrichExistingDependencies(
      Map<String, ProviderReport> providers,
      Map<String, Map<String, String>> hashes,
      String packagePrefix,
      BiFunction<String, String, Optional<PackageRef>> registryQuery) {
    Set<String> processedPurls = new HashSet<>();

    for (var providerEntry : providers.entrySet()) {
      var providerReport = providerEntry.getValue();
      if (providerReport == null
          || providerReport.getSources() == null
          || providerReport.getSources().isEmpty()) {
        continue;
      }

      for (var sourceEntry : providerReport.getSources().entrySet()) {
        var sourceReport = sourceEntry.getValue();
        if (sourceReport == null || sourceReport.getDependencies() == null) {
          continue;
        }

        for (var depReport : sourceReport.getDependencies()) {
          if (depReport == null || depReport.getRef() == null) {
            continue;
          }

          String purlRef = depReport.getRef().ref();
          if (purlRef == null || !purlRef.startsWith(packagePrefix)) {
            continue;
          }

          processedPurls.add(purlRef);

          if (depReport.getRecommendation() != null) {
            continue;
          }

          Map<String, String> purlHashes = hashes.get(purlRef);
          String sbomSha256 = (purlHashes != null) ? purlHashes.get(HASH_ALG_SHA256) : null;
          Optional<PackageRef> recommendedRef = registryQuery.apply(purlRef, sbomSha256);
          if (recommendedRef.isEmpty()) {
            continue;
          }

          var trustedContent = new RemediationTrustedContent().ref(recommendedRef.get());

          if (depReport.getIssues() != null) {
            depReport
                .getIssues()
                .forEach(
                    issue -> {
                      var existing = issue.getRemediation();
                      if (existing == null) {
                        existing = new Remediation();
                      }
                      existing.trustedContent(trustedContent);
                      issue.remediation(existing);
                    });
          }

          // Backward compat: set deprecated per-dependency recommendation
          depReport.recommendation(recommendedRef.get());

          // Populate provider-level recommendations map
          addToRecommendationsMap(providerReport, depReport.getRef(), recommendedRef.get());
        }
      }
    }

    return processedPurls;
  }

  private void enrichUnreportedDependencies(
      Map<String, ProviderReport> providers,
      DependencyTree tree,
      Map<String, Map<String, String>> hashes,
      String packagePrefix,
      BiFunction<String, String, Optional<PackageRef>> registryQuery,
      Set<String> processedPurls) {
    for (PackageRef pkgRef : tree.getAll()) {
      String purlRef = pkgRef.ref();
      if (purlRef == null || !purlRef.startsWith(packagePrefix)) {
        continue;
      }
      if (processedPurls.contains(purlRef)) {
        continue;
      }

      Map<String, String> purlHashes = hashes.get(purlRef);
      String sbomSha256 = (purlHashes != null) ? purlHashes.get(HASH_ALG_SHA256) : null;
      Optional<PackageRef> recommendedRef = registryQuery.apply(purlRef, sbomSha256);
      if (recommendedRef.isEmpty()) {
        continue;
      }

      // Backward compat: add deprecated per-dependency recommendation to a source
      var depReport = new DependencyReport().ref(pkgRef).recommendation(recommendedRef.get());

      for (var providerEntry : providers.entrySet()) {
        var providerReport = providerEntry.getValue();
        if (providerReport == null) {
          continue;
        }
        if (providerReport.getSources() == null) {
          providerReport.sources(new HashMap<>());
        }
        if (providerReport.getSources().isEmpty()) {
          var defaultSource = new Source();
          defaultSource.dependencies(new ArrayList<>());
          defaultSource.summary(new SourceSummary());
          providerReport.getSources().put(providerEntry.getKey(), defaultSource);
        }
        for (var sourceEntry : providerReport.getSources().entrySet()) {
          var sourceReport = sourceEntry.getValue();
          if (sourceReport != null) {
            sourceReport.addDependenciesItem(depReport);
            break;
          }
        }

        // Populate provider-level recommendations map
        addToRecommendationsMap(providerReport, pkgRef, recommendedRef.get());
        break;
      }
    }
  }

  /**
   * Adds a recommendation entry to the provider-level "trusted-libraries" recommendation source.
   */
  private void addToRecommendationsMap(
      ProviderReport providerReport, PackageRef ref, PackageRef recommendedRef) {
    if (providerReport.getRecommendations() == null) {
      providerReport.recommendations(new HashMap<>());
    }
    var recSource =
        providerReport
            .getRecommendations()
            .computeIfAbsent(
                TRUSTED_LIBRARIES_SOURCE,
                k ->
                    new RecommendationSource()
                        .summary(new RecommendationSummary().total(0))
                        .dependencies(new ArrayList<>()));
    var recReport = new RecommendationReport().ref(ref).recommendation(recommendedRef);
    recSource.addDependenciesItem(recReport);
    recSource.getSummary().total(recSource.getDependencies().size());
  }

  private void recountRecommendations(Map<String, ProviderReport> providers) {
    for (var providerEntry : providers.entrySet()) {
      var providerReport = providerEntry.getValue();
      if (providerReport == null || providerReport.getSources() == null) {
        continue;
      }
      for (var sourceEntry : providerReport.getSources().entrySet()) {
        var sourceReport = sourceEntry.getValue();
        if (sourceReport == null
            || sourceReport.getDependencies() == null
            || sourceReport.getSummary() == null) {
          continue;
        }
        int recCount =
            (int)
                sourceReport.getDependencies().stream()
                    .filter(d -> d.getRecommendation() != null)
                    .count();
        sourceReport.getSummary().setRecommendations(recCount);
      }
    }
  }
}
