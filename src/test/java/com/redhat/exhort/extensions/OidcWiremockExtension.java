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

import java.util.HashMap;
import java.util.Map;

public class OidcWiremockExtension extends WiremockExtension {

  private static final String CLIENT_ID = "test-tpa-client";
  private static final String CLIENT_SECRET = "test-tpa-secret";

  @Override
  public Map<String, String> start() {
    var base = super.start();

    stubTpaClientToken();
    var oidcConfig = new HashMap<>(base);

    oidcConfig.put("keycloak.url", server.baseUrl());
    return oidcConfig;
  }

  protected void stubTpaClientToken() {
    server.stubFor(
        com.github.tomakehurst.wiremock.client.WireMock.post("/auth/realms/tpa/token")
            .withBasicAuth(CLIENT_ID, CLIENT_SECRET)
            .withHeader(
                "Content-Type",
                com.github.tomakehurst.wiremock.client.WireMock.equalTo(
                    "application/x-www-form-urlencoded"))
            .withRequestBody(containing("grant_type=client_credentials"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        String.format(
                            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":300}",
                            TPA_TOKEN))));

    String openIdConfigJson =
        String.format(
            """
            {
              "jwks_uri": "%1$s/auth/realms/tpa/protocol/openid-connect/certs",
              "token_introspection_endpoint": "%1$s/auth/realms/tpa/protocol/openid-connect/token/introspect",
              "authorization_endpoint": "%1$s/auth/realms/tpa",
              "userinfo_endpoint": "%1$s/auth/realms/tpa/protocol/openid-connect/userinfo",
              "token_endpoint": "%1$s/auth/realms/tpa/token",
              "issuer" : "https://server.example.com",
              "introspection_endpoint": "%1$s/auth/realms/tpa/protocol/openid-connect/token/introspect",
              "end_session_endpoint": "%1$s/auth/realms/tpa/protocol/openid-connect/end-session"
            }
            """,
            server.baseUrl());

    server.stubFor(
        com.github.tomakehurst.wiremock.client.WireMock.get(
                "/realms/tpa/.well-known/openid-configuration")
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(openIdConfigJson)));
  }
}
