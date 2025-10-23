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

package io.github.guacsec.trustifyda.model.trustedcontent;

import java.util.*;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public record Recommendations(
    @JsonProperty("recommendations") Map<String, List<TcRecommendation>> matchings) {

  public Recommendations {
    if (matchings == null) {
      matchings = new HashMap<>();
    }
  }

  public Map<String, List<TcRecommendation>> getMatchings() {
    return matchings;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    public Map<String, List<TcRecommendation>> matchings;

    public Builder matchings(Map<String, List<TcRecommendation>> matchings) {
      this.matchings = matchings;
      return this;
    }

    public Recommendations build() {
      return new Recommendations(this.matchings);
    }
  }
}
