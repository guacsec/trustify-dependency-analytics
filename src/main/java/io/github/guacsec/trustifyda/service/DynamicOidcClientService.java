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

package io.github.guacsec.trustifyda.service;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.model.trustify.ProviderAuthConfig;
import io.github.guacsec.trustifyda.model.trustify.ProviderConfig;
import io.github.guacsec.trustifyda.model.trustify.ProvidersConfig;
import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.client.OidcClients;
import io.quarkus.oidc.client.runtime.OidcClientConfig;
import io.quarkus.runtime.Startup;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class DynamicOidcClientService {

  private static final int TOKEN_TIMEOUT = 10;
  private static final int OIDC_TIMEOUT = 30;

  private static final Logger LOGGER = Logger.getLogger(DynamicOidcClientService.class);

  @Inject ProvidersConfig providersConfig;

  @Inject OidcClients oidcClients;

  @Inject ObjectMapper objectMapper;

  private final Map<String, OidcClient> dynamicClients = new ConcurrentHashMap<>();

  @Startup
  void onStart() {
    if (providersConfig != null && providersConfig.providers() != null) {
      for (Map.Entry<String, ProviderConfig> entry : providersConfig.providers().entrySet()) {
        String providerKey = entry.getKey();
        ProviderConfig config = entry.getValue();

        if (config.auth() != null && config.auth().isPresent()) {
          ProviderAuthConfig authConfig = config.auth().get();
          createOidcClient(providerKey, authConfig);
        }
      }
    }
  }

  private void createOidcClient(String providerKey, ProviderAuthConfig authConfig) {
    try {
      // Create OIDC client configuration using the builder
      OidcClientConfig clientConfig =
          OidcClientConfig.builder()
              .id(providerKey)
              .authServerUrl(authConfig.serverUrl())
              .clientId(authConfig.clientId())
              .credentials(authConfig.clientSecret())
              .grant(OidcClientConfig.Grant.Type.CLIENT)
              .build();

      // Create the OIDC client
      OidcClient client =
          oidcClients.newClient(clientConfig).await().atMost(Duration.ofSeconds(OIDC_TIMEOUT));
      dynamicClients.put(providerKey, client);

      LOGGER.info("Created OIDC client for provider: " + providerKey);
    } catch (Exception e) {
      LOGGER.error(
          "Failed to create OIDC client for provider " + providerKey + ": " + e.getMessage());
    }
  }

  public OidcClient getClient(String providerKey) {
    return dynamicClients.get(providerKey);
  }

  public String getToken(String providerKey) {
    OidcClient client = dynamicClients.get(providerKey);
    if (client != null) {
      try {
        return client
            .getTokens()
            .await()
            .atMost(Duration.ofSeconds(TOKEN_TIMEOUT))
            .getAccessToken();
      } catch (Exception e) {
        LOGGER.error("Failed to get token for provider " + providerKey + ": " + e.getMessage());
      }
    }
    return null;
  }

  public boolean hasClient(String providerKey) {
    return dynamicClients.containsKey(providerKey);
  }

  /**
   * Validates a token using the introspection endpoint directly. This method makes an HTTP call to
   * the introspection endpoint to validate the token.
   *
   * @param providerKey The provider key to get the auth configuration
   * @param token The token to validate
   * @return true if the token is valid, false otherwise
   */
  public boolean validateToken(String providerKey, String token) {
    if (providersConfig == null || providersConfig.providers() == null) {
      LOGGER.warn("No providers configuration available");
      return false;
    }

    var providerConfig = providersConfig.providers().get(providerKey);
    if (providerConfig == null || !providerConfig.auth().isPresent()) {
      LOGGER.warn("No auth configuration found for provider: " + providerKey);
      return false;
    }

    var authConfig = providerConfig.auth().get();
    try {
      // Build introspection endpoint URL
      String introspectionUrl =
          authConfig.serverUrl() + "/protocol/openid-connect/token/introspect";

      // Create HTTP client
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

      // Prepare the request body
      String requestBody =
          "token="
              + URLEncoder.encode(token, StandardCharsets.UTF_8)
              + "&token_type_hint=access_token";

      // Create basic auth header
      String credentials = authConfig.clientId() + ":" + authConfig.clientSecret();
      String basicAuth = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());

      // Create HTTP request
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create(introspectionUrl))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .header("Authorization", basicAuth)
              .POST(HttpRequest.BodyPublishers.ofString(requestBody))
              .timeout(Duration.ofSeconds(30))
              .build();

      LOGGER.info("Validating token using introspection endpoint: " + introspectionUrl);

      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 200) {
        String responseBody = response.body();
        LOGGER.debug("Introspection response: " + responseBody);
        var responseObj = objectMapper.readTree(responseBody);
        if (responseObj.get("active") == null) {
          LOGGER.warn("Active field not found in introspection response");
          return false;
        }
        return responseObj.get("active").asBoolean();
      }
      if (response.statusCode() == 401) {
        LOGGER.warn("Token introspection failed with status: " + response.statusCode());
        return false;
      }
      if (response.statusCode() == 500) {
        throw new ServerErrorException(
            "Token introspection failed for provider " + providerKey + ": " + response.body(),
            Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
      }

    } catch (IOException | InterruptedException e) {
      LOGGER.error(
          "Token introspection failed for provider " + providerKey + ": " + e.getMessage(), e);
      throw new ServerErrorException(
          "Token introspection failed for provider " + providerKey + ": " + e.getMessage(),
          Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
    }
    return false;
  }
}
