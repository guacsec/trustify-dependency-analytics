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

import java.util.Map;
import java.util.Set;

import org.apache.camel.Body;
import org.apache.camel.ExchangeProperty;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.trustedcontent.CachedRecommendation;
import io.github.guacsec.trustifyda.model.trustedcontent.TrustedContentResponse;

public interface CacheService {

  public void cacheRecommendations(
      @Body TrustedContentResponse response,
      @ExchangeProperty(Constants.CACHED_RECOMMENDATIONS_PROPERTY) Set<PackageRef> misses);

  public Map<PackageRef, CachedRecommendation> getRecommendations(Set<PackageRef> purls);
}
