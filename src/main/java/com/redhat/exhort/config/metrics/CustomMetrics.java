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

package com.redhat.exhort.config.metrics;

import java.util.Collection;
import java.util.List;

import io.micrometer.core.instrument.Meter.Id;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

@Singleton
public class CustomMetrics {

  private static final String HTTP_SERVER_REQUESTS_METRIC = "http.server.requests";
  private static final String CAMEL_ROUTES_METRIC = "camel.route.policy";
  private static final String ROUTE_ID_TAG = "routeId";

  private static final double SECOND = 1000000000.0;

  private static final Collection<String> MONITORED_ROUTES =
      List.of(
          "getTrustedContent",
          "trustifyRequest",
          "analyticsIdentify",
          "analyticsTrackAnalysis",
          "analyticsTrackToken",
          "processFailedRequests");

  @Produces
  @Singleton
  public MeterFilter enableHistogram() {
    return new MeterFilter() {
      @Override
      public DistributionStatisticConfig configure(Id id, DistributionStatisticConfig config) {
        if (requiresHistogram(id)) {
          return DistributionStatisticConfig.builder()
              .percentiles(0.90, 0.95, 0.99)
              .percentilesHistogram(Boolean.FALSE)
              .serviceLevelObjectives(
                  0.01 * SECOND,
                  0.025 * SECOND,
                  0.05 * SECOND,
                  0.1 * SECOND,
                  0.25 * SECOND,
                  0.5 * SECOND,
                  1 * SECOND,
                  2.5 * SECOND,
                  5 * SECOND,
                  10 * SECOND)
              .build()
              .merge(config);
        }
        return config;
      }
    };
  }

  private boolean requiresHistogram(Id id) {
    if (HTTP_SERVER_REQUESTS_METRIC.equalsIgnoreCase(id.getName())) {
      return true;
    }
    if (CAMEL_ROUTES_METRIC.equalsIgnoreCase(id.getName())) {
      String routeTag = id.getTag(ROUTE_ID_TAG);
      if (routeTag == null) {
        return false;
      }
      return MONITORED_ROUTES.contains(routeTag);
    }
    return false;
  }
}
