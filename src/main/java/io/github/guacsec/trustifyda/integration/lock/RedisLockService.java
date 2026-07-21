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

package io.github.guacsec.trustifyda.integration.lock;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.jboss.logging.Logger;

import io.vertx.mutiny.redis.client.RedisAPI;
import io.vertx.mutiny.redis.client.Response;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Redis-based distributed lock following the single-instance Redlock pattern. Uses {@code SET NX
 * EX} for atomic acquisition and a Lua script for atomic owner-checked release.
 */
@ApplicationScoped
public class RedisLockService implements LockService {

  private static final Logger LOG = Logger.getLogger(RedisLockService.class);

  private static final String RELEASE_SCRIPT =
      "if redis.call('get', KEYS[1]) == ARGV[1] then "
          + "return redis.call('del', KEYS[1]) "
          + "else "
          + "return 0 "
          + "end";

  private final RedisAPI redis;
  private final String instanceId = UUID.randomUUID().toString();

  public RedisLockService(RedisAPI redis) {
    this.redis = redis;
  }

  @Override
  public boolean tryAcquire(String key, Duration ttl) {
    Response response =
        redis
            .set(List.of(key, instanceId, "NX", "EX", String.valueOf(ttl.getSeconds())))
            .await()
            .indefinitely();
    return response != null && "OK".equals(response.toString());
  }

  @Override
  public void release(String key) {
    try {
      redis.eval(List.of(RELEASE_SCRIPT, "1", key, instanceId)).await().indefinitely();
    } catch (Exception e) {
      LOG.warnf(e, "Failed to release distributed lock: %s", key);
    }
  }
}
