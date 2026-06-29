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

package io.github.guacsec.trustifyda.model;

import java.util.Collections;
import java.util.List;

import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.model.trustify.Recommendation;

/**
 * Aggregated data for a single package: its recommendations, vulnerability issues, and warnings.
 */
public record PackageItem(
    String packageRef,
    Recommendation recommendation,
    List<Recommendation> allRecommendations,
    List<Issue> issues,
    List<String> warnings,
    String recommendationSource) {

  /** Compact constructor that defaults null allRecommendations to a singleton list. */
  public PackageItem {
    if (allRecommendations == null || allRecommendations.isEmpty()) {
      allRecommendations =
          recommendation != null ? List.of(recommendation) : Collections.emptyList();
    }
  }

  /** Backward-compatible constructor without allRecommendations and recommendationSource. */
  public PackageItem(
      String packageRef, Recommendation recommendation, List<Issue> issues, List<String> warnings) {
    this(packageRef, recommendation, null, issues, warnings, null);
  }

  /** Backward-compatible constructor without allRecommendations. */
  public PackageItem(
      String packageRef,
      Recommendation recommendation,
      List<Issue> issues,
      List<String> warnings,
      String recommendationSource) {
    this(packageRef, recommendation, null, issues, warnings, recommendationSource);
  }
}
