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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.ProviderStatus;
import io.github.guacsec.trustifyda.model.trustedcontent.IndexedRecommendation;
import io.github.guacsec.trustifyda.model.trustedcontent.TrustedContentResponse;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.inject.Inject;

@QuarkusTest
public class RedisCacheServiceTest {

  private static final PackageRef[] TEST_PURLS = {
    new PackageRef("pkg:maven/io.quarkus/quarkus-core@2.13.6.Final"),
    new PackageRef("pkg:maven/io.quarkus/quarkus-arc@2.13.6.Final")
  };

  @Inject CacheService cacheService;

  @Test
  void testFailedResponse() {
    var failedResponse =
        new TrustedContentResponse(buildRecommendations(), new ProviderStatus().ok(Boolean.FALSE));
    cacheService.cacheRecommendations(failedResponse, Set.of(TEST_PURLS));

    assertTrue(cacheService.getRecommendations(Set.of(TEST_PURLS)).isEmpty());
  }

  @Test
  void testCacheAllData() {
    var failedResponse =
        new TrustedContentResponse(buildRecommendations(), new ProviderStatus().ok(Boolean.TRUE));
    cacheService.cacheRecommendations(failedResponse, Set.of(TEST_PURLS));

    var cachedData = cacheService.getRecommendations(Set.of(TEST_PURLS));
    assertEquals(2, cachedData.size());
    Stream.of(TEST_PURLS)
        .forEach(
            p -> {
              var cachedPurl = cachedData.get(p);
              assertNotNull(cachedPurl);
              assertEquals(p, cachedPurl.ref());
              assertEquals(
                  p.ref() + "-redhat-00001", cachedPurl.recommendation().packageName().ref());
            });
  }

  private Map<PackageRef, IndexedRecommendation> buildRecommendations() {
    return Stream.of(TEST_PURLS)
        .collect(
            Collectors.toMap(
                p -> p,
                p ->
                    new IndexedRecommendation(
                        new PackageRef(p.ref() + "-redhat-00001"), Collections.emptyMap())));
  }
}
