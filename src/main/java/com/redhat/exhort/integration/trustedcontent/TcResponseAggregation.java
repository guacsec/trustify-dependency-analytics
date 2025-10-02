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

package com.redhat.exhort.integration.trustedcontent;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.apache.camel.AggregationStrategy;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangeProperty;

import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.ProviderStatus;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.cache.CacheService;
import com.redhat.exhort.model.trustedcontent.IndexedRecommendation;
import com.redhat.exhort.model.trustedcontent.TrustedContentCachedRequest;
import com.redhat.exhort.model.trustedcontent.TrustedContentResponse;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Response.Status;

@Singleton
@RegisterForReflection
public class TcResponseAggregation implements AggregationStrategy {

  @Inject CacheService cacheService;

  @Override
  public Exchange aggregate(Exchange oldExchange, Exchange newExchange) {
    oldExchange.setProperty(
        Constants.TRUSTED_CONTENT_PROVIDER,
        newExchange.getIn().getBody(TrustedContentResponse.class));
    return oldExchange;
  }

  public TrustedContentResponse aggregateCachedResponse(
      @ExchangeProperty(Constants.CACHED_RECOMMENDATIONS_PROPERTY)
          TrustedContentCachedRequest cached,
      Exchange exchange)
      throws ExecutionException {

    var externalResponse = exchange.getIn().getBody(TrustedContentResponse.class);
    if (externalResponse == null) {
      externalResponse =
          new TrustedContentResponse(
              Collections.emptyMap(),
              new ProviderStatus()
                  .name(Constants.TRUSTED_CONTENT_PROVIDER)
                  .code(Status.OK.getStatusCode())
                  .message(Status.OK.getReasonPhrase())
                  .ok(Boolean.TRUE));
    }
    cacheService.cacheRecommendations(externalResponse, cached.miss());
    Map<PackageRef, IndexedRecommendation> recommendations =
        new HashMap<>(externalResponse.recommendations());
    cacheService.cacheRecommendations(externalResponse, cached.miss());
    recommendations.putAll(cached.cached());
    exchange.removeProperty(Constants.CACHED_RECOMMENDATIONS_PROPERTY);
    return new TrustedContentResponse(recommendations, externalResponse.status());
  }

  public TrustedContentResponse aggregateEmptyResponse(Exchange exchange) {
    return new TrustedContentResponse(
        new HashMap<>(),
        new ProviderStatus()
            .name(Constants.TRUSTED_CONTENT_PROVIDER)
            .code(Status.OK.getStatusCode())
            .message(Status.OK.getReasonPhrase())
            .ok(Boolean.TRUE));
  }
}
