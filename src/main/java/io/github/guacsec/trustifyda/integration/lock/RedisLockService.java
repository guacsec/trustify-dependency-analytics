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
import java.util.UUID;

import org.jboss.logging.Logger;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.SetArgs;
import io.quarkus.redis.datasource.value.ValueCommands;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Redis-based distributed lock implementation. Each instance is identified by a random UUID to
 * ensure only the lock owner can release it. Uses atomic SET NX EX GET to prevent race conditions.
 */
@ApplicationScoped
public class RedisLockService implements LockService {

  private static final Logger LOG = Logger.getLogger(RedisLockService.class);

  private final ValueCommands<String, String> lockCommands;
  private final KeyCommands<String> keyCommands;
  private final String instanceId = UUID.randomUUID().toString();

  public RedisLockService(RedisDataSource ds) {
    this.lockCommands = ds.value(String.class);
    this.keyCommands = ds.key();
  }

  @Override
  public boolean tryAcquire(String key, Duration ttl) {
    String previous = lockCommands.setGet(key, instanceId, new SetArgs().nx().ex(ttl));
    return previous == null;
  }

  @Override
  public void release(String key) {
    try {
      String currentHolder = lockCommands.get(key);
      if (instanceId.equals(currentHolder)) {
        keyCommands.del(key);
      }
    } catch (Exception e) {
      LOG.warnf(e, "Failed to release distributed lock: %s", key);
    }
  }
}
