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

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import java.util.Map;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

public class WiremockExtension implements QuarkusTestResourceLifecycleManager {

  public static final String SNYK_TOKEN = "snyk-token-xyz";
  public static final String TPA_TOKEN = "tpa-token-abc";

  private final WireMockServer server = new WireMockServer(options().dynamicPort());

  @Override
  public Map<String, String> start() {
    server.start();

    return Map.of(
        "api.snyk.host", server.baseUrl(),
        "api.snyk.token", SNYK_TOKEN,
        "api.trustedcontent.host", server.baseUrl(),
        "api.ossindex.host", server.baseUrl(),
        "api.tpa.host", server.baseUrl(),
        "api.tpa.token", TPA_TOKEN);
  }

  @Override
  public void stop() {
    if (server != null) {
      server.stop();
    }
  }

  @Override
  public void inject(TestInjector testInjector) {
    testInjector.injectIntoFields(
        server,
        new TestInjector.AnnotatedAndMatchesType(InjectWireMock.class, WireMockServer.class));
  }
}
