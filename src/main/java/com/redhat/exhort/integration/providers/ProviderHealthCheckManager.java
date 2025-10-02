/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.providers;

import java.util.HashMap;
import java.util.Map;

import org.apache.camel.CamelContext;
import org.apache.camel.builder.ExchangeBuilder;
import org.apache.camel.health.HealthCheck;
import org.apache.camel.health.HealthCheckRegistry;
import org.apache.camel.health.HealthCheckResultBuilder;
import org.apache.camel.impl.health.AbstractHealthCheck;

import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.model.ProviderHealthCheckResult;
import com.redhat.exhort.model.trustify.ProvidersConfig;

import io.quarkus.runtime.Startup;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class ProviderHealthCheckManager {

  @Inject CamelContext camelContext;

  private HealthCheckRegistry registry() {
    return camelContext.hasService(HealthCheckRegistry.class);
  }

  @Inject ProvidersConfig configuration;

  @Startup
  public void registerHealthChecks() {
    configuration
        .providers()
        .forEach(
            (name, config) -> {
              HealthCheck check =
                  new AbstractHealthCheck(name) {

                    @Override
                    protected void doCall(
                        HealthCheckResultBuilder builder, Map<String, Object> options) {
                      if (config.disabled()) {
                        builder.up();
                        builder.details(Map.of("disabled", config.disabled()));
                        return;
                      }
                      var response =
                          getCamelContext()
                              .createProducerTemplate()
                              .send(
                                  "direct:trustifyHealthCheck",
                                  ExchangeBuilder.anExchange(getCamelContext())
                                      .withProperty(Constants.PROVIDER_NAME_PROPERTY, name)
                                      .withBody(config)
                                      .build());
                      var result = response.getMessage().getBody(ProviderHealthCheckResult.class);

                      if (result.ok()) {
                        builder.up();
                      } else {
                        builder.down();
                        Map<String, Object> details = new HashMap<>();
                        details.put("code", result.code());
                        details.put("message", result.message());
                        builder.details(details);
                      }
                    }
                  };
              registry().register(check);
            });
  }
}
