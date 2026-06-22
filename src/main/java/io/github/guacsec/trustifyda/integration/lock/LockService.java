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

/**
 * Distributed lock abstraction for coordinating exclusive operations across multiple application
 * replicas.
 */
public interface LockService {

  /**
   * Attempts to acquire a distributed lock with the given key and TTL.
   *
   * @param key the lock key
   * @param ttl the lock expiration duration (safety net if the holder crashes)
   * @return {@code true} if the lock was acquired, {@code false} if held by another instance
   */
  boolean tryAcquire(String key, Duration ttl);

  /**
   * Releases the lock only if this instance still holds it.
   *
   * @param key the lock key
   */
  void release(String key);
}
