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

package com.redhat.exhort.integration.providers.osv;

import java.util.HashMap;
import java.util.Map;

import org.apache.camel.builder.ExchangeBuilder;
import org.apache.camel.health.HealthCheckResultBuilder;
import org.apache.camel.impl.health.AbstractHealthCheck;
import org.apache.camel.spi.annotations.HealthCheck;

import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.model.ProviderHealthCheckResult;

@HealthCheck(Constants.OSV_PROVIDER)
public class OsvHealthCheck extends AbstractHealthCheck {

  public OsvHealthCheck() {
    super(Constants.OSV_PROVIDER);
  }

  @Override
  protected void doCall(HealthCheckResultBuilder builder, Map<String, Object> options) {
    ProviderHealthCheckResult result;
    try {
      var response =
          getCamelContext()
              .createProducerTemplate()
              .send("direct:osvHealthCheck", ExchangeBuilder.anExchange(getCamelContext()).build());

      result = response.getMessage().getBody(ProviderHealthCheckResult.class);

    } catch (Exception e) {
      result = ProviderHealthCheckResult.error(Constants.OSV_PROVIDER, 500, e.getMessage());
    }

    if (result == null) {
      result = ProviderHealthCheckResult.error(Constants.OSV_PROVIDER, 500, "Health check failed");
    }

    if (result.ok()) {
      builder.up();
      if (result.disabled()) {
        builder.details(Map.of("disabled", result.disabled()));
      }
    } else {
      builder.down();
      Map<String, Object> details = new HashMap<>();
      details.put("code", result.code());
      details.put("message", result.message());
      builder.details(details);
    }
  }
}
