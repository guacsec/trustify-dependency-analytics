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

package io.github.guacsec.trustifyda.model.trustify;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory index mapping base image references to hardened image recommendations.
 * Reads are lock-free via volatile reference swap on update.
 */
public class HardenedImageIndex {

  private volatile Map<String, List<IndexedRecommendation>> index = new ConcurrentHashMap<>();

  /**
   * Atomically replaces the entire index with the given data. Concurrent readers will see either
   * the old or new map — never a partially updated state.
   */
  public void replaceAll(Map<String, List<IndexedRecommendation>> newData) {
    this.index = new ConcurrentHashMap<>(newData);
  }

  /** Looks up all hardened image recommendations for the given base image reference. */
  public List<IndexedRecommendation> get(String baseImageRef) {
    return index.getOrDefault(baseImageRef, Collections.emptyList());
  }

  /** Returns an unmodifiable view of the current index. */
  public Map<String, List<IndexedRecommendation>> getAll() {
    return Collections.unmodifiableMap(index);
  }

  /** Returns the number of base image entries in the index. */
  public int size() {
    return index.size();
  }
}
