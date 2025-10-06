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
import java.util.Optional;

import org.apache.camel.CamelContext;
import org.apache.camel.builder.ExchangeBuilder;
import org.apache.camel.health.HealthCheckRegistry;
import org.apache.camel.health.HealthCheckResultBuilder;
import org.apache.camel.impl.health.AbstractHealthCheck;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.model.ProviderHealthCheckResult;
import com.redhat.exhort.model.trustify.ProviderAuthConfig;
import com.redhat.exhort.model.trustify.ProviderConfig;
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

  @ConfigProperty(name = "api.onguard.disabled", defaultValue = "false")
  boolean onguardDisabled;

  @ConfigProperty(name = "api.onguard.management.host", defaultValue = "http://onguard:9000/")
  String onguardManagementHost;

  @Startup
  public void registerHealthChecks() {
    configuration
        .providers()
        .forEach(
            (name, config) -> {
              registry().register(new ProviderHealthCheck(name, config, "trustifyHealthCheck"));
            });

    registerOsvHealthCheck();
  }

  private static class ProviderHealthCheck extends AbstractHealthCheck {
    private final ProviderConfig config;
    private final String healthCheckRoute;

    public ProviderHealthCheck(String name, ProviderConfig config, String healthCheckRoute) {
      super(name);
      this.config = config;
      this.healthCheckRoute = healthCheckRoute;
    }

    @Override
    protected void doCall(HealthCheckResultBuilder builder, Map<String, Object> options) {
      if (config.disabled()) {
        builder.up();
        builder.details(Map.of("disabled", config.disabled()));
        return;
      }
      var response =
          getCamelContext()
              .createProducerTemplate()
              .send(
                  "direct:" + healthCheckRoute,
                  ExchangeBuilder.anExchange(getCamelContext())
                      .withProperty(Constants.PROVIDER_NAME_PROPERTY, this.getId())
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
  }

  private void registerOsvHealthCheck() {
    ProviderConfig osvConfig =
        new ProviderConfig() {
          @Override
          public boolean disabled() {
            return onguardDisabled;
          }

          @Override
          public String host() {
            return onguardManagementHost;
          }

          @Override
          public Optional<ProviderAuthConfig> auth() {
            return Optional.empty();
          }
        };
    registry()
        .register(new ProviderHealthCheck(Constants.OSV_PROVIDER, osvConfig, "osvHealthCheck"));
  }
}
