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

package io.github.guacsec.trustifyda.integration.licenses;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import io.github.guacsec.trustifyda.api.v5.LicenseCategory;
import io.github.guacsec.trustifyda.api.v5.LicenseIdentifier;
import io.github.guacsec.trustifyda.api.v5.LicenseInfo;
import io.github.guacsec.trustifyda.api.v5.LicensesSummary;
import io.github.guacsec.trustifyda.api.v5.PackageLicenseResult;

public class LicenseSummaryUtils {

  private LicenseSummaryUtils() {}

  public static LicensesSummary buildSummary(Map<String, PackageLicenseResult> results) {
    List<LicenseInfo> allInfos =
        results.values().stream()
            .map(PackageLicenseResult::getEvidence)
            .flatMap(List::stream)
            .filter(Objects::nonNull)
            .toList();
    Map<String, Long> summaryCount =
        allInfos.stream()
            .filter(Objects::nonNull)
            .flatMap(
                info ->
                    (info.getIdentifiers() != null
                            ? info.getIdentifiers()
                            : List.<LicenseIdentifier>of())
                        .stream())
            .filter(Objects::nonNull)
            .flatMap(
                id -> {
                  List<String> labels = new ArrayList<>();
                  if (Boolean.TRUE.equals(id.getIsDeprecated())) {
                    labels.add("DEPRECATED");
                  }
                  if (Boolean.TRUE.equals(id.getIsOsiApproved())) {
                    labels.add("OSI_APPROVED");
                  }
                  if (Boolean.TRUE.equals(id.getIsFsfLibre())) {
                    labels.add("FSF_LIBRE");
                  }
                  if (id.getCategory() != null) {
                    labels.add(id.getCategory().name());
                  }
                  labels.add("TOTAL");
                  return labels.stream();
                })
            .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));

    return new LicensesSummary()
        .total(summaryCount.getOrDefault("TOTAL", 0L).intValue())
        .concluded(results.size())
        .permissive(summaryCount.getOrDefault(LicenseCategory.PERMISSIVE.name(), 0L).intValue())
        .weakCopyleft(
            summaryCount.getOrDefault(LicenseCategory.WEAK_COPYLEFT.name(), 0L).intValue())
        .strongCopyleft(
            summaryCount.getOrDefault(LicenseCategory.STRONG_COPYLEFT.name(), 0L).intValue())
        .unknown(summaryCount.getOrDefault(LicenseCategory.UNKNOWN.name(), 0L).intValue())
        .fsfLibre(summaryCount.getOrDefault("FSF_LIBRE", 0L).intValue())
        .osiApproved(summaryCount.getOrDefault("OSI_APPROVED", 0L).intValue())
        .deprecated(summaryCount.getOrDefault("DEPRECATED", 0L).intValue());
  }
}
