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

package io.github.guacsec.trustifyda.integration.trustedcontent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.camel.Exchange;
import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.cache.CacheService;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.DirectDependency;
import io.github.guacsec.trustifyda.model.trustedcontent.CachedRecommendation;
import io.github.guacsec.trustifyda.model.trustedcontent.IndexedRecommendation;
import io.github.guacsec.trustifyda.model.trustedcontent.TrustedContentCachedRequest;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.inject.Inject;

@QuarkusTest
public class TrustedContentRequestBuilderTest {

  private static final PackageRef[] TEST_PURLS = {
    new PackageRef("pkg:maven/io.quarkus/quarkus-core@2.13.6.Final"),
    new PackageRef("pkg:maven/io.quarkus/quarkus-arc@2.13.6.Final"),
    new PackageRef("pkg:maven/io.quarkus/quarkus-vertx@2.13.6.Final")
  };

  @Inject TrustedContentRequestBuilder requestBuilder;

  @InjectMock CacheService cacheService;

  @Test
  void testFilterCachedRecommendations_noDeps() {
    Exchange exchange = mock();
    DependencyTree tree = new DependencyTree(Collections.emptyMap());
    var deps = tree.getAll();

    when(cacheService.getRecommendations(deps)).thenReturn(Collections.emptyMap());

    var result = requestBuilder.filterCachedRecommendations(tree, exchange);

    assertTrue(result.isEmpty());
    verify(exchange)
        .setProperty(
            eq(Constants.CACHED_RECOMMENDATIONS_PROPERTY),
            argThat(
                req -> {
                  var tcReq = (TrustedContentCachedRequest) req;
                  return tcReq.cached().isEmpty() && tcReq.miss().isEmpty();
                }));
  }

  @Test
  void testFilterCachedRecommendations_noCachedData() {
    Exchange exchange = mock();
    DependencyTree tree = buildDeps();
    var deps = tree.getAll();

    when(cacheService.getRecommendations(deps)).thenReturn(Collections.emptyMap());

    var result = requestBuilder.filterCachedRecommendations(tree, exchange);

    assertEquals(deps.size(), result.size());
    verify(exchange)
        .setProperty(
            eq(Constants.CACHED_RECOMMENDATIONS_PROPERTY),
            argThat(
                req -> {
                  var tcReq = (TrustedContentCachedRequest) req;
                  return tcReq.cached().isEmpty() && tcReq.miss().size() == TEST_PURLS.length;
                }));
  }

  @Test
  void testFilterCachedRecommendations_emptyCachedData() {
    Exchange exchange = mock();
    DependencyTree tree = buildDeps();
    var deps = tree.getAll();

    var cachedData =
        Stream.of(TEST_PURLS)
            .collect(Collectors.toMap(p -> p, p -> new CachedRecommendation(p, null)));
    when(cacheService.getRecommendations(deps)).thenReturn(cachedData);

    var result = requestBuilder.filterCachedRecommendations(tree, exchange);

    assertTrue(result.isEmpty());
    verify(exchange)
        .setProperty(
            eq(Constants.CACHED_RECOMMENDATIONS_PROPERTY),
            argThat(
                req -> {
                  var tcReq = (TrustedContentCachedRequest) req;
                  return tcReq.cached().isEmpty() && tcReq.miss().isEmpty();
                }));
  }

  @Test
  void testFilterCachedRecommendations_partialCache() {
    Exchange exchange = mock();
    DependencyTree tree = buildDeps();
    var deps = tree.getAll();

    var cachedData =
        Map.of(
            TEST_PURLS[0],
            new CachedRecommendation(TEST_PURLS[0], null),
            TEST_PURLS[1],
            new CachedRecommendation(
                TEST_PURLS[1],
                new IndexedRecommendation(
                    new PackageRef(TEST_PURLS[1].ref() + "-redhat-0001"), null)));
    when(cacheService.getRecommendations(deps)).thenReturn(cachedData);

    var result = requestBuilder.filterCachedRecommendations(tree, exchange);

    assertEquals(1, result.size());
    assertTrue(result.contains(TEST_PURLS[2]));
    verify(exchange)
        .setProperty(
            eq(Constants.CACHED_RECOMMENDATIONS_PROPERTY),
            argThat(
                req -> {
                  var tcReq = (TrustedContentCachedRequest) req;
                  return tcReq.cached().size() == 1
                      && tcReq.cached().containsKey(TEST_PURLS[1])
                      && tcReq.miss().contains(TEST_PURLS[2]);
                }));
  }

  private DependencyTree buildDeps() {
    var deps =
        Stream.of(TEST_PURLS).collect(Collectors.toMap(d -> d, d -> new DirectDependency(d, null)));
    return new DependencyTree(deps);
  }
}
