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

import java.util.Optional;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.registry.Pep691Response;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;

@ApplicationScoped
public class Pep691Integration extends EndpointRouteBuilder {

  private static final Logger LOGGER = Logger.getLogger(Pep691Integration.class);

  private static final String PEP691_ACCEPT = "application/vnd.pypi.simple.v1+json";
  private static final String PKG_PYPI_PREFIX = "pkg:pypi/";
  private static final String PEP691_URL_PROPERTY = "pep691RegistryUrl";
  private static final String PEP691_PACKAGE_PROPERTY = "pep691PackageName";

  @ConfigProperty(name = "api.pypi.registry.host", defaultValue = "")
  String registryHost;

  @ConfigProperty(name = "api.pypi.registry.timeout", defaultValue = "10s")
  String timeout;

  private final RegistryEnrichmentService enrichmentService = new RegistryEnrichmentService();

  @Inject ObjectMapper objectMapper;

  @Inject ProducerTemplate producerTemplate;

  @Override
  public void configure() {
    // fmt:off
    from(direct("enrichPypiRecommendations"))
      .routeId("enrichPypiRecommendations")
      .process(this::enrichRecommendations);

    from(direct("pep691Lookup"))
      .routeId("pep691Lookup")
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .process(this::processPep691Request)
        .toD("${exchangeProperty.pep691RegistryUrl}?throwExceptionOnFailure=false")
      .onFallback()
        .process(this::handleLookupFallback)
      .end();
    // fmt:on
  }

  private void processPep691Request(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_RAW_QUERY);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Exchange.HTTP_PATH);
    message.removeHeader(Exchange.HTTP_HOST);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.removeHeader(Exchange.CONTENT_TYPE);

    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.GET);
    message.setHeader("Accept", PEP691_ACCEPT);

    String packageName = exchange.getProperty(PEP691_PACKAGE_PROPERTY, String.class);
    message.setHeader(Exchange.HTTP_PATH, "/" + packageName + "/");
  }

  private void handleLookupFallback(Exchange exchange) {
    exchange.getMessage().setHeader(Exchange.HTTP_RESPONSE_CODE, 504);
    exchange.getMessage().setBody(null);
  }

  void enrichRecommendations(Exchange exchange) {
    if (registryHost == null || registryHost.isBlank()) {
      return;
    }

    var body = exchange.getIn().getBody();
    if (!(body instanceof AnalysisReport report)) {
      return;
    }

    DependencyTree tree =
        exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class);
    if (tree == null) {
      return;
    }

    enrichmentService.enrichReport(report, tree, PKG_PYPI_PREFIX, this::queryRegistryAndCompare);
  }

  Optional<PackageRef> queryRegistryAndCompare(String purlRef, String sbomSha256) {
    try {
      PackageRef ref = PackageRef.builder().purl(purlRef).build();
      String name = ref.name();
      String version = ref.version();
      if (name == null || version == null) {
        return Optional.empty();
      }

      String normalizedName = name.toLowerCase().replace("-", "_").replace(".", "_");
      String baseUrl = registryHost.replaceAll("/+$", "");

      Exchange response =
          producerTemplate.send(
              "direct:pep691Lookup",
              ex -> {
                ex.setProperty(PEP691_URL_PROPERTY, baseUrl);
                ex.setProperty(PEP691_PACKAGE_PROPERTY, normalizedName);
              });

      Integer statusCode =
          response.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE, Integer.class);
      if (statusCode == null || statusCode != 200) {
        LOGGER.debugf("PEP 691 registry returned %s for %s", statusCode, name);
        return Optional.empty();
      }

      String responseBody = response.getMessage().getBody(String.class);
      Pep691Response pep691Response = objectMapper.readValue(responseBody, Pep691Response.class);
      if (pep691Response == null
          || pep691Response.files() == null
          || pep691Response.files().isEmpty()) {
        return Optional.empty();
      }

      String filePrefix = normalizedName + "-" + version;
      for (var file : pep691Response.files()) {
        if (file.filename() == null || file.hashes() == null) {
          continue;
        }
        if (!matchesVersion(file.filename(), filePrefix)) {
          continue;
        }
        String registrySha256 = file.hashes().get("sha256");
        if (registrySha256 != null) {
          if (sbomSha256 != null && registrySha256.equalsIgnoreCase(sbomSha256)) {
            return Optional.empty();
          }
          return Optional.of(
              PackageRef.builder()
                  .purl(PKG_PYPI_PREFIX + name + "@" + version + "?repository_url=" + baseUrl)
                  .build());
        }
      }

      return Optional.empty();
    } catch (Exception e) {
      LOGGER.debugf("PEP 691 registry lookup failed for %s: %s", purlRef, e.getMessage());
      return Optional.empty();
    }
  }

  private boolean matchesVersion(String filename, String prefix) {
    String normalizedFilename = filename.toLowerCase().replace("-", "_").replace(".", "_");
    String normalizedPrefix = prefix.toLowerCase().replace("-", "_").replace(".", "_");
    if (!normalizedFilename.startsWith(normalizedPrefix)) {
      return false;
    }
    if (normalizedFilename.length() == normalizedPrefix.length()) {
      return true;
    }
    char next = filename.charAt(prefix.length());
    return next == '-' || next == '.' || next == '_';
  }
}
