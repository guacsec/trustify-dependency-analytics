/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
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

package com.redhat.exhort.extensions;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;

import java.util.HashMap;
import java.util.Map;

import com.github.tomakehurst.wiremock.WireMockServer;

public class OidcWiremockExtension extends WiremockExtension {

  public static final String CLIENT_ID = "test-trustify-client";
  public static final String CLIENT_SECRET = "test-trustify-secret";

  @Override
  public Map<String, String> start() {
    var base = super.start();

    stubTrustifyClientToken();
    var oidcConfig = new HashMap<>(base);

    oidcConfig.put("keycloak.url", server.baseUrl());
    return oidcConfig;
  }

  /**
   * Re-stub OIDC endpoints after server reset. This method should be called after server.resetAll()
   * to restore OIDC stubs.
   */
  public static void restubOidcEndpoints(WireMockServer server) {
    // Re-stub OIDC token endpoint
    server.stubFor(
        post(urlMatching(".*/auth/realms/.*/token.*"))
            .withBasicAuth(CLIENT_ID, CLIENT_SECRET)
            .withHeader("Content-Type", equalTo("application/x-www-form-urlencoded"))
            .withRequestBody(containing("grant_type=client_credentials"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        String.format(
                            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":300}",
                            TRUSTIFY_TOKEN))));

    // Re-stub OpenID configuration endpoint
    String openIdConfigJson =
        String.format(
            """
            {
              "jwks_uri": "%1$s/auth/realms/trustify/protocol/openid-connect/certs",
              "token_introspection_endpoint": "%1$s/auth/realms/trustify/protocol/openid-connect/token/introspect",
              "authorization_endpoint": "%1$s/auth/realms/trustify",
              "userinfo_endpoint": "%1$s/auth/realms/trustify/protocol/openid-connect/userinfo",
              "token_endpoint": "%1$s/auth/realms/trustify/token",
              "issuer" : "https://server.example.com",
              "introspection_endpoint": "%1$s/auth/realms/trustify/protocol/openid-connect/token/introspect",
              "end_session_endpoint": "%1$s/auth/realms/trustify/protocol/openid-connect/end-session"
            }
            """,
            server.baseUrl());

    server.stubFor(
        get("/realms/trustify/.well-known/openid-configuration")
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(openIdConfigJson)));
  }

  protected void stubTrustifyClientToken() {
    server.stubFor(
        post(urlMatching(".*/auth/realms/.*/token.*"))
            .withBasicAuth(CLIENT_ID, CLIENT_SECRET)
            .withHeader("Content-Type", equalTo("application/x-www-form-urlencoded"))
            .withRequestBody(containing("grant_type=client_credentials"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        String.format(
                            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":300}",
                            TRUSTIFY_TOKEN))));

    String openIdConfigJson =
        String.format(
            """
            {
              "jwks_uri": "%1$s/auth/realms/trustify/protocol/openid-connect/certs",
              "token_introspection_endpoint": "%1$s/auth/realms/trustify/protocol/openid-connect/token/introspect",
              "authorization_endpoint": "%1$s/auth/realms/trustify",
              "userinfo_endpoint": "%1$s/auth/realms/trustify/protocol/openid-connect/userinfo",
              "token_endpoint": "%1$s/auth/realms/trustify/token",
              "issuer" : "https://server.example.com",
              "introspection_endpoint": "%1$s/auth/realms/trustify/protocol/openid-connect/token/introspect",
              "end_session_endpoint": "%1$s/auth/realms/trustify/protocol/openid-connect/end-session"
            }
            """,
            server.baseUrl());

    server.stubFor(
        get("/realms/trustify/.well-known/openid-configuration")
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(openIdConfigJson)));
  }
}
