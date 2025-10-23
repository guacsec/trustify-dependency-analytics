/*
 * Copyright 2023-2025 Trustify Dependency Analytics Authors
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

package io.github.guacsec.trustifyda.integration.cache;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.model.trustedcontent.CachedRecommendation;
import io.github.guacsec.trustifyda.model.trustedcontent.TrustedContentResponse;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.value.ValueCommands;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class RedisCacheService implements CacheService {

  @ConfigProperty(name = "recommendations.cache.ttl", defaultValue = "1d")
  Duration recommendationTtl;

  private final ValueCommands<String, CachedRecommendation> recommendationsCommands;

  public RedisCacheService(RedisDataSource ds) {
    this.recommendationsCommands = ds.value(CachedRecommendation.class);
  }

  @Override
  public void cacheRecommendations(TrustedContentResponse response, Set<PackageRef> misses) {
    if (response == null || response.status() == null || !response.status().getOk()) {
      return;
    }
    misses.stream()
        .forEach(
            v ->
                recommendationsCommands.psetex(
                    "recommendations:" + v.ref(),
                    recommendationTtl.toMillis(),
                    new CachedRecommendation(v, response.recommendations().get(v))));
  }

  @Override
  public Map<PackageRef, CachedRecommendation> getRecommendations(Set<PackageRef> purls) {
    if (purls == null || purls.isEmpty()) {
      return Collections.emptyMap();
    }
    var result =
        recommendationsCommands.mget(
            purls.stream().map(p -> "recommendations:" + p.ref()).toArray(String[]::new));
    return result.values().stream()
        .filter(Objects::nonNull)
        .collect(Collectors.toMap(v -> v.ref(), v -> v));
  }
}
