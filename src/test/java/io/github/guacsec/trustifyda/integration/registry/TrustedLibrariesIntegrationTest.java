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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.DependencyTree;

import jakarta.enterprise.inject.Instance;

public class TrustedLibrariesIntegrationTest {

  private TrustedLibrariesIntegration integration;
  private Exchange exchange;
  private Message message;

  @SuppressWarnings("unchecked")
  @BeforeEach
  void setUp() {
    integration = new TrustedLibrariesIntegration();
    integration.registryIntegrations = mock(Instance.class);
    exchange = mock(Exchange.class);
    message = mock(Message.class);
    when(exchange.getIn()).thenReturn(message);
  }

  @Test
  void skipWhenBodyNotAnalysisReport() {
    when(message.getBody()).thenReturn("not a report");

    integration.enrichAll(exchange);

    verify(integration.registryIntegrations, never()).iterator();
  }

  @Test
  void skipWhenDependencyTreeNull() {
    var report = new AnalysisReport();
    when(message.getBody()).thenReturn(report);
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(null);

    integration.enrichAll(exchange);

    verify(integration.registryIntegrations, never()).iterator();
  }

  @Test
  void callEnabledRegistries() {
    var report = new AnalysisReport();
    var tree =
        DependencyTree.builder()
            .dependencies(Collections.emptyMap())
            .componentHashes(Collections.emptyMap())
            .build();
    when(message.getBody()).thenReturn(report);
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(tree);

    RegistryIntegration enabled = mock(RegistryIntegration.class);
    when(enabled.isEnabled()).thenReturn(true);

    RegistryIntegration disabled = mock(RegistryIntegration.class);
    when(disabled.isEnabled()).thenReturn(false);

    when(integration.registryIntegrations.iterator())
        .thenReturn(List.of(enabled, disabled).iterator());

    integration.enrichAll(exchange);

    verify(enabled).enrich(report, tree);
    verify(disabled, never()).enrich(any(), any());
  }

  @Test
  void continueOnRegistryFailure() {
    var report = new AnalysisReport();
    var tree =
        DependencyTree.builder()
            .dependencies(Collections.emptyMap())
            .componentHashes(Collections.emptyMap())
            .build();
    when(message.getBody()).thenReturn(report);
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(tree);

    RegistryIntegration failing = mock(RegistryIntegration.class);
    when(failing.isEnabled()).thenReturn(true);
    doThrow(new RuntimeException("boom")).when(failing).enrich(any(), any());

    RegistryIntegration healthy = mock(RegistryIntegration.class);
    when(healthy.isEnabled()).thenReturn(true);

    when(integration.registryIntegrations.iterator())
        .thenReturn(List.of(failing, healthy).iterator());

    integration.enrichAll(exchange);

    verify(failing).enrich(report, tree);
    verify(healthy).enrich(report, tree);
  }

  @Test
  void noRegistriesConfigured() {
    var report = new AnalysisReport();
    var tree =
        DependencyTree.builder()
            .dependencies(Collections.emptyMap())
            .componentHashes(Collections.emptyMap())
            .build();
    when(message.getBody()).thenReturn(report);
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(tree);

    when(integration.registryIntegrations.iterator()).thenReturn(Collections.emptyIterator());

    integration.enrichAll(exchange);
  }
}
