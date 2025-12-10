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
import java.util.function.Function;
import java.util.stream.Collectors;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.value.ValueCommands;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class RedisCacheService implements CacheService {

  private static final Logger LOGGER = Logger.getLogger(RedisCacheService.class);

  @ConfigProperty(name = "items.cache.ttl", defaultValue = "1d")
  Duration itemTtl;

  private final ValueCommands<String, PackageItem> itemsCommands;

  public RedisCacheService(RedisDataSource ds) {
    this.itemsCommands = ds.value(PackageItem.class);
  }

  @Override
  public void cacheItems(ProviderResponse response, Set<PackageRef> misses) {
    if (response == null
        || response.status() == null
        || response.pkgItems() == null
        || misses == null
        || misses.isEmpty()) {
      return;
    }
    misses.stream()
        .forEach(
            v -> {
              var item = response.pkgItems().get(v.ref());
              if (item != null) {
                itemsCommands.psetex("items:" + v.ref(), itemTtl.toMillis(), item);
              } else {
                itemsCommands.psetex(
                    "items:" + v.ref(),
                    itemTtl.toMillis(),
                    new PackageItem(
                        v.ref(), null, Collections.emptyList(), Collections.emptyList()));
              }
            });
    LOGGER.debugf("Cached %d items", misses.size());
  }

  @Override
  public Map<PackageRef, PackageItem> getCachedItems(Set<PackageRef> purls) {
    if (purls == null || purls.isEmpty()) {
      return Collections.emptyMap();
    }
    var result =
        itemsCommands.mget(purls.stream().map(p -> "items:" + p.ref()).toArray(String[]::new));
    LOGGER.debugf("Got %d cached items for %d purls", result.size(), purls.size());
    return result.values().stream()
        .filter(Objects::nonNull)
        .collect(Collectors.toMap(v -> new PackageRef(v.packageRef()), Function.identity()));
  }
}
