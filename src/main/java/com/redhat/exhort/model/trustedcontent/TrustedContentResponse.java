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

package com.redhat.exhort.model.trustedcontent;

import java.util.Collections;
import java.util.Map;

import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.ProviderStatus;

public record TrustedContentResponse(
    Map<PackageRef, IndexedRecommendation> recommendations, ProviderStatus status) {

  public TrustedContentResponse {
    if (recommendations == null) {
      recommendations = Collections.emptyMap();
    }
    if (status == null) {
      status = new ProviderStatus();
    }
  }
}
