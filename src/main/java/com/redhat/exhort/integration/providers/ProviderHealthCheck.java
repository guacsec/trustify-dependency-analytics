/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.camel.health.HealthCheckResultBuilder;
import org.apache.camel.impl.health.AbstractHealthCheck;

import com.redhat.exhort.api.v4.ProviderStatus;

public class ProviderHealthCheck extends AbstractHealthCheck {

  private static final List<String> ALL_PROVIDERS_HEALTH_CHECKS =
      List.of("direct:osvHealthCheck", "direct:tpaHealthCheck");

  public ProviderHealthCheck() {
    super("External Providers Readiness Check");
  }

  @Override
  protected void doCall(HealthCheckResultBuilder builder, Map<String, Object> options) {
    builder.up();
    // TODO: Temporarily disabled while investigating TC-1067
    // var response =
    //     getCamelContext()
    //         .createProducerTemplate()
    //         .send(
    //             "direct:exhortHealthCheck",
    //             ExchangeBuilder.anExchange(getCamelContext())
    //                 .withHeader(
    //                     Constants.HEALTH_CHECKS_LIST_HEADER_NAME, ALL_PROVIDERS_HEALTH_CHECKS)
    //                 .build());

    // List<ProviderStatus> httpResponseBodiesAndStatuses =
    //     (List<ProviderStatus>) response.getMessage().getBody();
    // Map<String, Object> providers =
    //     httpResponseBodiesAndStatuses.stream()
    //         .collect(
    //             Collectors.toMap(
    //                 provider -> provider.getName(),
    //                 provider -> formatProviderStatus(provider),
    //                 (a, b) -> a));
    // builder.details(providers);

    // if (httpResponseBodiesAndStatuses.stream()
    //     .filter(providerStatus -> Objects.nonNull(providerStatus.getCode()))
    //     .anyMatch(providerDetails -> providerDetails.getCode() < 400 && providerDetails.getOk()))
    // {
    //   builder.up();

    // } else {
    //   builder.down();
    // }
  }

  private static String formatProviderStatus(ProviderStatus provider) {
    if (Objects.nonNull(provider.getCode())) {
      return String.format(
          "providerName=%s, isEnabled=%s, statusCode=%s, message=%s",
          provider.getName(), provider.getOk(), provider.getCode(), provider.getMessage());
    } else {
      return String.format(
          "providerName=%s, isEnabled=%s, message=%s",
          provider.getName(), provider.getOk(), provider.getMessage());
    }
  }

  @Override
  public boolean isLiveness() {
    return false;
  }
}
