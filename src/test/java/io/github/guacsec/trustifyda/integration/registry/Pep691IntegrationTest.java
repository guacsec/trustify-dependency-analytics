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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.DependencyReport;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.model.DependencyTree;

public class Pep691IntegrationTest {

  private Pep691Integration integration;

  @BeforeEach
  void setUp() {
    integration = new Pep691Integration();
  }

  @Test
  void disabledWhenRegistryHostEmpty() {
    integration.registryHost = "";
    assertFalse(integration.isEnabled());
  }

  @Test
  void disabledWhenRegistryHostNull() {
    integration.registryHost = null;
    assertFalse(integration.isEnabled());
  }

  @Test
  void enabledWhenRegistryHostConfigured() {
    integration.registryHost = "https://registry.example.com";
    assertTrue(integration.isEnabled());
  }

  @Test
  void enrichWithNoComponentHashes() {
    integration.registryHost = "https://registry.example.com";
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    var tree =
        DependencyTree.builder()
            .dependencies(Collections.emptyMap())
            .componentHashes(Collections.emptyMap())
            .build();

    integration.enrich(report, tree);

    var dep = getFirstDep(report);
    assertNull(dep.getRecommendation());
  }

  private AnalysisReport buildReportWithPypiDep(String purl) {
    var dep = new DependencyReport();
    dep.ref(PackageRef.builder().purl(purl).build());

    var source = new Source();
    source.dependencies(new ArrayList<>(List.of(dep)));

    var providerReport = new ProviderReport();
    providerReport.sources(Map.of("source1", source));

    var report = new AnalysisReport();
    report.providers(Map.of("provider1", providerReport));
    return report;
  }

  private DependencyReport getFirstDep(AnalysisReport report) {
    return report
        .getProviders()
        .values()
        .iterator()
        .next()
        .getSources()
        .values()
        .iterator()
        .next()
        .getDependencies()
        .get(0);
  }
}
