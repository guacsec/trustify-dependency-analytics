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

package io.github.guacsec.trustifyda.integration.providers.trustify.hardened;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/** Configuration for the Hummingbird hardened image recommendation provider. */
@ConfigMapping(prefix = "trustedcontent.recommendation.hardened")
public interface HardenedImageRecommendation {

  /** Registry prefix replacement map: source prefix → target prefix. */
  Map<String, String> registryMap();

  /** Hummingbird service URL. When empty, the provider is disabled. */
  Optional<String> url();

  /** Interval between periodic data refreshes from the Hummingbird service. */
  @WithDefault("1h")
  String refreshInterval();

  /** TTL for the Redis distributed lock used during refresh. */
  @WithDefault("5m")
  Duration lockTtl();
}
