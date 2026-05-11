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

import org.apache.camel.Exchange;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.jboss.logging.Logger;

import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.DependencyTree;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

@ApplicationScoped
public class TrustedLibrariesIntegration extends EndpointRouteBuilder {

  private static final Logger LOGGER = Logger.getLogger(TrustedLibrariesIntegration.class);

  @Inject Instance<RegistryIntegration> registryIntegrations;

  @Override
  public void configure() {
    // fmt:off
    from(direct("enrichTrustedLibraries"))
      .routeId("enrichTrustedLibraries")
      .process(this::enrichAll);
    // fmt:on
  }

  void enrichAll(Exchange exchange) {
    var body = exchange.getIn().getBody();
    if (!(body instanceof AnalysisReport report)) {
      return;
    }

    DependencyTree tree =
        exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class);
    if (tree == null) {
      return;
    }

    for (RegistryIntegration integration : registryIntegrations) {
      if (integration.isEnabled()) {
        try {
          integration.enrich(report, tree);
        } catch (Exception e) {
          LOGGER.warnf(
              "Registry enrichment failed for %s: %s",
              integration.getClass().getSimpleName(), e.getMessage());
        }
      }
    }
  }
}
