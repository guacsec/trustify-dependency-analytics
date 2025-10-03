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

package com.redhat.exhort.integration.providers.trustify;

import java.time.Duration;

import org.apache.camel.Exchange;
import org.apache.camel.Route;
import org.apache.camel.support.RoutePolicySupport;

import com.redhat.exhort.integration.Constants;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

public class ProviderRoutePolicy extends RoutePolicySupport {

  private final MeterRegistry registry;

  public ProviderRoutePolicy(MeterRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void onExchangeBegin(Route route, Exchange exchange) {
    exchange.setProperty("provider.timer.sample", Timer.start(registry));
  }

  @Override
  public void onExchangeDone(Route route, Exchange exchange) {
    Timer.Sample sample = exchange.getProperty("provider.timer.sample", Timer.Sample.class);
    if (sample != null) {
      var providerName = exchange.getProperty(Constants.PROVIDER_NAME_PROPERTY, String.class);
      if (providerName == null) {
        providerName = "unknown";
      }

      sample.stop(
          Timer.builder("camel.route.provider.requests")
              .tag("provider", providerName)
              .tag("routeId", route.getId())
              .description("Request latency per provider in trustifyScan")
              .publishPercentileHistogram()
              .publishPercentiles(0.90, 0.95, 0.99)
              .serviceLevelObjectives(
                  Duration.ofMillis(10),
                  Duration.ofMillis(25),
                  Duration.ofMillis(50),
                  Duration.ofMillis(100),
                  Duration.ofMillis(250),
                  Duration.ofMillis(500),
                  Duration.ofMillis(1000),
                  Duration.ofMillis(2500),
                  Duration.ofMillis(5000),
                  Duration.ofMillis(10000))
              .register(registry));
    }
  }
}
