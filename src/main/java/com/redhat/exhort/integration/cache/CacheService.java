/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.cache;

import java.util.Map;
import java.util.Set;

import org.apache.camel.Body;
import org.apache.camel.ExchangeProperty;

import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.model.trustedcontent.CachedRecommendation;
import com.redhat.exhort.model.trustedcontent.TrustedContentResponse;

public interface CacheService {

  public void cacheRecommendations(
      @Body TrustedContentResponse response,
      @ExchangeProperty(Constants.CACHED_RECOMMENDATIONS_PROPERTY) Set<PackageRef> misses);

  public Map<PackageRef, CachedRecommendation> getRecommendations(Set<PackageRef> purls);
}
