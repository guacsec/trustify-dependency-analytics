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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.integration.lock.LockService;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;

public class HardenedImageProviderTest {

  private static final String LOCK_KEY = "hardened-image-refresh-lock";
  private static final String HARDENED_NGINX_PURL =
      "pkg:oci/hardened-nginx@sha256:abc123?repository_url=registry.example.com/hardened-nginx&tag=1.25";

  /** Normalized PURL as produced by PackageURL (URL-encodes special characters). */
  private static String normalized(String rawPurl) {
    return new PackageRef(rawPurl).ref();
  }

  private HardenedImageProvider provider;
  private HardenedImageRecommendation config;
  private HardenedImageResponseHandler responseHandler;
  private LockService lock;
  private HummingbirdClient hummingbirdClient;

  @BeforeEach
  void setUp() {
    lock = mock(LockService.class);
    hummingbirdClient = mock(HummingbirdClient.class);
    responseHandler = new HardenedImageResponseHandler(new ObjectMapper());
    config = mock(HardenedImageRecommendation.class);
    when(config.lockTtl()).thenReturn(Duration.ofMinutes(5));
    when(config.refreshInterval()).thenReturn("1h");
    when(config.registryMap()).thenReturn(Collections.emptyMap());

    provider = new HardenedImageProvider(config, lock, responseHandler, hummingbirdClient);
  }

  // Verifies that the periodic refresh acquires the lock, fetches data, and populates the index.
  @Test
  void testRefreshAcquiresLockAndPopulatesIndex() throws Exception {
    // Given a configured URL and a lock that this instance acquires
    when(config.url()).thenReturn(Optional.of("http://hummingbird.example.com/report.json"));
    when(lock.tryAcquire(eq(LOCK_KEY), any())).thenReturn(true);

    // Spy on the provider to stub fetchAndParseData (avoids real HTTP)
    HardenedImageProvider spyProvider = spy(provider);

    IndexedRecommendation nginxRec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    doReturn(
            Map.of(
                "docker.io/library/nginx:1.25", List.of(nginxRec),
                "docker.io/library/nginx:1.25-alpine", List.of(nginxRec)))
        .when(spyProvider)
        .fetchAndParseData(anyString());

    // When the refresh runs
    spyProvider.refresh();

    // Then the lock was acquired and the index is populated
    verify(lock).tryAcquire(eq(LOCK_KEY), any());
    assertEquals(2, spyProvider.getIndex().size());
    assertFalse(spyProvider.lookup("docker.io/library/nginx:1.25").isEmpty());
    assertFalse(spyProvider.lookup("docker.io/library/nginx:1.25-alpine").isEmpty());
    assertEquals(
        normalized(HARDENED_NGINX_PURL),
        spyProvider.lookup("docker.io/library/nginx:1.25").get(0).packageName().ref());
    assertEquals(
        "hardened", spyProvider.lookup("docker.io/library/nginx:1.25").get(0).sourceName());
  }

  // Verifies that a second instance skips refresh when the lock is already held.
  @Test
  void testLockContentionSkipsRefresh() {
    // Given a configured URL but the lock is held by another instance
    when(config.url()).thenReturn(Optional.of("http://hummingbird.example.com/report.json"));
    when(lock.tryAcquire(eq(LOCK_KEY), any())).thenReturn(false);

    // When the refresh runs
    provider.refresh();

    // Then the index remains empty
    assertEquals(0, provider.getIndex().size());
  }

  // Verifies that Hummingbird response parsing correctly inverts the compare_to mapping.
  @Test
  void testParseAndInvertMapping() throws Exception {
    // Given a Hummingbird response with container image refs as keys (not PURLs)
    String json =
        "{\"images\": {"
            + "\"registry.example.com/hardened-python:3.12\":"
            + " {\"compare_to\": [\"docker.io/library/python:3.12\","
            + " \"docker.io/library/python:3.12-slim\"]},"
            + "\"registry.example.com/hardened-node:20\":"
            + " {\"compare_to\": [\"docker.io/library/node:20\"]}}}";

    // When parsing and inverting the mapping
    Map<String, List<IndexedRecommendation>> result = responseHandler.parseAndInvertMapping(json);

    // Then each base image maps to its hardened recommendation with an OCI PURL
    assertEquals(3, result.size());
    var pythonRecs = result.get("docker.io/library/python:3.12");
    assertNotNull(pythonRecs);
    assertEquals(1, pythonRecs.size());
    assertEquals("oci", pythonRecs.get(0).packageName().purl().getType());
    assertEquals("hardened-python", pythonRecs.get(0).packageName().purl().getName());
    assertEquals(
        pythonRecs.get(0).packageName().ref(),
        result.get("docker.io/library/python:3.12-slim").get(0).packageName().ref());

    var nodeRecs = result.get("docker.io/library/node:20");
    assertNotNull(nodeRecs);
    assertEquals(1, nodeRecs.size());
    assertEquals("oci", nodeRecs.get(0).packageName().purl().getType());
    assertEquals("hardened-node", nodeRecs.get(0).packageName().purl().getName());
    assertEquals("hardened", nodeRecs.get(0).sourceName());
  }

  // Verifies that the provider returns empty results when the Hummingbird URL is not configured.
  @Test
  void testDisabledWhenUrlNotConfigured() {
    // Given no Hummingbird URL configured
    when(config.url()).thenReturn(Optional.empty());

    // When the refresh runs
    provider.refresh();

    // Then no lock is acquired and lookup returns empty
    verify(lock, never()).tryAcquire(anyString(), any());
    assertTrue(provider.lookup("docker.io/library/nginx:1.25").isEmpty());
  }

  // Verifies that the lock is released after a successful data load.
  @Test
  void testLockReleasedAfterSuccessfulLoad() throws Exception {
    // Given a configured URL and a lock that this instance acquires
    when(config.url()).thenReturn(Optional.of("http://hummingbird.example.com/report.json"));
    when(lock.tryAcquire(eq(LOCK_KEY), any())).thenReturn(true);

    // Spy on the provider to stub fetchAndParseData (avoids real HTTP)
    HardenedImageProvider spyProvider = spy(provider);

    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    doReturn(Map.of("base:1.0", List.of(rec))).when(spyProvider).fetchAndParseData(anyString());

    // When refresh completes successfully
    spyProvider.refresh();

    // Then the lock is released and the index is populated
    verify(lock).release(LOCK_KEY);
    assertEquals(1, spyProvider.getIndex().size());
    assertFalse(spyProvider.lookup("base:1.0").isEmpty());
  }

  // Verifies that parsing handles the standard Hummingbird object format with container ref keys.
  @Test
  void testParseObjectFormat() throws Exception {
    // Given a Hummingbird response with a container image ref as key
    String json =
        "{\"images\": {"
            + "\"registry.example.com/hardened-alpine:3.19\":"
            + " {\"compare_to\": [\"docker.io/library/alpine:3.19\"]}}}";

    // When parsing
    Map<String, List<IndexedRecommendation>> result = responseHandler.parseAndInvertMapping(json);

    // Then the mapping is correctly inverted with an OCI PURL
    assertEquals(1, result.size());
    var recs = result.get("docker.io/library/alpine:3.19");
    assertNotNull(recs);
    assertEquals(1, recs.size());
    assertEquals("oci", recs.get(0).packageName().purl().getType());
    assertEquals("hardened-alpine", recs.get(0).packageName().purl().getName());
  }

  // Verifies that parsing returns empty index for responses with no images.
  @Test
  void testParseEmptyResponse() throws Exception {
    // Given an empty Hummingbird response
    String json = "{\"images\": {}}";

    // When parsing
    Map<String, List<IndexedRecommendation>> result = responseHandler.parseAndInvertMapping(json);

    // Then the result is empty
    assertTrue(result.isEmpty());
  }

  // Verifies that entries with blank keys or missing compare_to are skipped.
  @Test
  void testParseSkipsInvalidEntries() throws Exception {
    // Given a response with some invalid entries (blank key, missing compare_to)
    String json =
        "{\"images\": {"
            + "\"\": {\"compare_to\": [\"base:1.0\"]},"
            + "\"registry.example.com/hardened-nginx:1.25\":"
            + " {\"compare_to\": [\"base:3.0\"]},"
            + "\"registry.example.com/hardened-python:3.12\": {}}}";

    // When parsing
    Map<String, List<IndexedRecommendation>> result = responseHandler.parseAndInvertMapping(json);

    // Then only the valid entry with compare_to is indexed
    assertEquals(1, result.size());
    assertNotNull(result.get("base:3.0"));
    assertTrue(result.getOrDefault("base:1.0", Collections.emptyList()).isEmpty());
  }

  // Verifies that a populated index is preserved when Hummingbird returns empty data.
  @Test
  void testEmptyResponsePreservesExistingIndex() throws Exception {
    // Given a configured URL and a lock that this instance acquires
    when(config.url()).thenReturn(Optional.of("http://hummingbird.example.com/report.json"));
    when(lock.tryAcquire(eq(LOCK_KEY), any())).thenReturn(true);

    HardenedImageProvider spyProvider = spy(provider);

    // First refresh: populate the index with data
    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    doReturn(Map.of("base:1.0", List.of(rec))).when(spyProvider).fetchAndParseData(anyString());
    spyProvider.refresh();
    assertEquals(1, spyProvider.getIndex().size());

    // Second refresh: Hummingbird returns empty data
    doReturn(Collections.<String, List<IndexedRecommendation>>emptyMap())
        .when(spyProvider)
        .fetchAndParseData(anyString());
    spyProvider.refresh();

    // Then the existing index is preserved
    assertEquals(1, spyProvider.getIndex().size());
    assertFalse(spyProvider.lookup("base:1.0").isEmpty());
  }

  // Verifies that a populated index is preserved when fetchAndParseData throws an exception.
  @Test
  void testFetchFailurePreservesExistingIndex() throws Exception {
    // Given a configured URL and a lock that this instance acquires
    when(config.url()).thenReturn(Optional.of("http://hummingbird.example.com/report.json"));
    when(lock.tryAcquire(eq(LOCK_KEY), any())).thenReturn(true);

    HardenedImageProvider spyProvider = spy(provider);

    // First refresh: populate the index with data
    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    doReturn(Map.of("base:1.0", List.of(rec))).when(spyProvider).fetchAndParseData(anyString());
    spyProvider.refresh();
    assertEquals(1, spyProvider.getIndex().size());

    // Second refresh: fetchAndParseData throws (simulating HTTP failure)
    doThrow(new RuntimeException("Connection refused"))
        .when(spyProvider)
        .fetchAndParseData(anyString());
    spyProvider.refresh();

    // Then the existing index is preserved and the lock is released
    assertEquals(1, spyProvider.getIndex().size());
    assertFalse(spyProvider.lookup("base:1.0").isEmpty());
    verify(lock, atLeastOnce()).release(LOCK_KEY);
  }

  // Verifies that lock release failure does not propagate and the index remains intact.
  @Test
  void testLockReleaseFailureDoesNotPropagate() throws Exception {
    // Given a configured URL and a lock that this instance acquires
    when(config.url()).thenReturn(Optional.of("http://hummingbird.example.com/report.json"));
    when(lock.tryAcquire(eq(LOCK_KEY), any())).thenReturn(true);

    HardenedImageProvider spyProvider = spy(provider);

    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    doReturn(Map.of("base:1.0", List.of(rec))).when(spyProvider).fetchAndParseData(anyString());

    // Lock release throws (simulating Redis connection failure)
    doThrow(new RuntimeException("Redis connection lost")).when(lock).release(LOCK_KEY);

    // When refresh runs — should not throw despite lock release failure
    spyProvider.refresh();

    // Then the index is still populated (refresh completed before the finally block)
    assertEquals(1, spyProvider.getIndex().size());
    assertFalse(spyProvider.lookup("base:1.0").isEmpty());
  }

  // Verifies that lookupBySbomId returns the recommendation for a matching OCI PURL.
  @Test
  void testLookupBySbomIdMatchingOciPurl() {
    // Given an index populated with a hardened nginx recommendation
    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    provider.getIndex().replaceAll(Map.of("docker.io/library/nginx:1.25", List.of(rec)));

    // When looking up by OCI PURL with matching repository_url and tag
    String ociPurl =
        "pkg:oci/nginx@sha256:def456?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25";
    var result = provider.lookupBySbomId(ociPurl);

    // Then the recommendation is returned
    assertEquals(1, result.size());
    var entry = result.entrySet().iterator().next();
    assertEquals(1, entry.getValue().size());
    assertEquals(normalized(HARDENED_NGINX_PURL), entry.getValue().get(0).packageName().ref());
    assertEquals("hardened", entry.getValue().get(0).sourceName());
  }

  // Verifies that lookupBySbomId returns empty for a non-OCI PURL.
  @Test
  void testLookupBySbomIdNonOciPurl() {
    // Given any index state
    // When looking up by a Maven PURL
    var result = provider.lookupBySbomId("pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar");

    // Then the result is empty
    assertTrue(result.isEmpty());
  }

  // Verifies that lookupBySbomId returns empty for a malformed PURL instead of throwing.
  @Test
  void testLookupBySbomIdWithMalformedPurl() {
    assertTrue(provider.lookupBySbomId("not-a-valid-purl").isEmpty());
  }

  // Verifies that lookupBySbomId returns empty for a null sbomId.
  @Test
  void testLookupBySbomIdNull() {
    assertTrue(provider.lookupBySbomId(null).isEmpty());
  }

  // Verifies that lookupBySbomId returns empty for an OCI PURL with no index match.
  @Test
  void testLookupBySbomIdNoMatch() {
    // Given an empty index
    // When looking up by an OCI PURL
    String ociPurl =
        "pkg:oci/alpine@sha256:abc?repository_url=docker.io%2Flibrary%2Falpine&tag=3.19";
    var result = provider.lookupBySbomId(ociPurl);

    // Then the result is empty
    assertTrue(result.isEmpty());
  }

  // Verifies that multiple hardened images sharing the same compare_to base are all preserved.
  @Test
  void testParseAndInvertMappingPreservesMultipleRecommendationsPerBase() throws Exception {
    // Given a Hummingbird response where two hardened images both replace the same base image
    String json =
        "{\"images\": {"
            + "\"registry.example.com/hardened-nginx-v1:1.25\":"
            + " {\"compare_to\": [\"docker.io/library/nginx:1.25\"]},"
            + "\"registry.example.com/hardened-nginx-v2:1.25\":"
            + " {\"compare_to\": [\"docker.io/library/nginx:1.25\","
            + " \"docker.io/library/nginx:1.25-alpine\"]}}}";

    // When parsing and inverting the mapping
    Map<String, List<IndexedRecommendation>> result = responseHandler.parseAndInvertMapping(json);

    // Then the shared base image has both hardened recommendations
    var nginxRecs = result.get("docker.io/library/nginx:1.25");
    assertNotNull(nginxRecs);
    assertEquals(
        2, nginxRecs.size(), "Both hardened images should be preserved for the shared base image");
    var recNames = nginxRecs.stream().map(r -> r.packageName().purl().getName()).sorted().toList();
    assertEquals(List.of("hardened-nginx-v1", "hardened-nginx-v2"), recNames);

    // And the non-shared base image has only one recommendation
    var alpineRecs = result.get("docker.io/library/nginx:1.25-alpine");
    assertNotNull(alpineRecs);
    assertEquals(1, alpineRecs.size());
    assertEquals("hardened-nginx-v2", alpineRecs.get(0).packageName().purl().getName());
  }

  // Verifies that lookupBySbomId returns all recommendations when multiple hardened images match.
  @Test
  void testLookupBySbomIdReturnsMultipleRecommendations() {
    // Given an index with two hardened images for the same base
    IndexedRecommendation recV1 =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    String hardenedV2Purl =
        "pkg:oci/hardened-nginx-v2@sha256:def789?repository_url=registry.example.com/hardened-nginx-v2&tag=1.25";
    IndexedRecommendation recV2 =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(hardenedV2Purl))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    provider.getIndex().replaceAll(Map.of("docker.io/library/nginx:1.25", List.of(recV1, recV2)));

    // When looking up by OCI PURL
    String ociPurl =
        "pkg:oci/nginx@sha256:def456?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25";
    var result = provider.lookupBySbomId(ociPurl);

    // Then both recommendations are returned
    assertEquals(1, result.size());
    var recommendations = result.entrySet().iterator().next().getValue();
    assertEquals(2, recommendations.size(), "Both hardened alternatives should be returned");
  }

  // Verifies that lookupBySbomId skips digest-pinned source images (no tag, version is sha256).
  @Test
  void testLookupBySbomIdSkipsDigestPinnedImage() {
    // Given an index with a hardened recommendation for nginx
    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    provider.getIndex().replaceAll(Map.of("docker.io/library/nginx:1.25", List.of(rec)));

    // When looking up by a digest-pinned OCI PURL (no tag, version is sha256)
    String digestPurl =
        "pkg:oci/nginx@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            + "?repository_url=docker.io%2Flibrary%2Fnginx";
    var result = provider.lookupBySbomId(digestPurl);

    // Then no recommendation is returned
    assertTrue(result.isEmpty(), "Digest-pinned images should not get recommendations");
  }

  // Verifies that lookupBySbomId uses the tag when both sha256 version and tag are present.
  @Test
  void testLookupBySbomIdUsesTagWhenDigestAndTagPresent() {
    // Given an index with a hardened recommendation for nginx
    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(HARDENED_NGINX_PURL))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    provider.getIndex().replaceAll(Map.of("docker.io/library/nginx:1.25", List.of(rec)));

    // When looking up by a PURL with both sha256 version and tag qualifier
    String digestWithTagPurl =
        "pkg:oci/nginx@sha256:abc123?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25";
    var result = provider.lookupBySbomId(digestWithTagPurl);

    // Then the recommendation is returned (tag qualifier enables lookup)
    assertEquals(1, result.size(), "Tag-qualified images should get recommendations");
  }

  // Verifies that the registry map replaces the prefix in recommended image PURLs.
  @Test
  void testLookupBySbomIdAppliesRegistryMap() {
    // Given an index with a hardened recommendation and a registry map configured
    String hardenedPurl =
        "pkg:oci/hardened-nginx?repository_url=quay.io/hummingbird/hardened-nginx&tag=1.25";
    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(hardenedPurl))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    provider.getIndex().replaceAll(Map.of("docker.io/library/nginx:1.25", List.of(rec)));
    when(config.registryMap())
        .thenReturn(Map.of("quay.io/hummingbird", "registry.access.redhat.com/hi"));

    // When looking up by OCI PURL
    String ociPurl = "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25";
    var result = provider.lookupBySbomId(ociPurl);

    // Then the recommendation's repository_url has the replaced prefix
    assertEquals(1, result.size());
    var mapped = result.entrySet().iterator().next().getValue().get(0);
    assertEquals(
        "registry.access.redhat.com/hi/hardened-nginx",
        mapped.packageName().purl().getQualifiers().get("repository_url"));
    assertEquals("1.25", mapped.packageName().purl().getQualifiers().get("tag"));
    assertEquals("hardened", mapped.sourceName());
  }

  // Verifies that lookupBySbomId returns bare image names when no registry map is configured.
  @Test
  void testLookupBySbomIdNoRegistryMapReturnsBareNames() {
    // Given an index with a hardened recommendation and NO registry map
    String hardenedPurl =
        "pkg:oci/hardened-nginx?repository_url=quay.io/hummingbird/hardened-nginx&tag=1.25";
    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(hardenedPurl))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    provider.getIndex().replaceAll(Map.of("docker.io/library/nginx:1.25", List.of(rec)));
    when(config.registryMap()).thenReturn(Collections.emptyMap());

    // When looking up by OCI PURL
    String ociPurl = "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25";
    var result = provider.lookupBySbomId(ociPurl);

    // Then the recommendation's repository_url is unchanged
    assertEquals(1, result.size());
    var recommendation = result.entrySet().iterator().next().getValue().get(0);
    assertEquals(
        "quay.io/hummingbird/hardened-nginx",
        recommendation.packageName().purl().getQualifiers().get("repository_url"));
  }

  // Verifies that applyRegistryMap correctly replaces a matching prefix.
  @Test
  void testApplyRegistryMapMatchingPrefix() {
    // Given a PackageRef with a repository_url matching a map entry
    String purl =
        "pkg:oci/hardened-nginx?repository_url=quay.io/hummingbird/hardened-nginx&tag=1.25";
    PackageRef ref = new PackageRef(purl);
    Map<String, String> registryMap =
        Map.of("quay.io/hummingbird", "registry.access.redhat.com/hi");

    // When applying the registry map
    PackageRef result = HardenedImageResponseHandler.applyRegistryMap(ref, registryMap);

    // Then the repository_url prefix is replaced
    assertNotEquals(ref.ref(), result.ref());
    assertEquals(
        "registry.access.redhat.com/hi/hardened-nginx",
        result.purl().getQualifiers().get("repository_url"));
    assertEquals("1.25", result.purl().getQualifiers().get("tag"));
  }

  // Verifies that applyRegistryMap returns the original ref when no prefix matches.
  @Test
  void testApplyRegistryMapNoMatch() {
    // Given a PackageRef with a repository_url NOT matching any map entry
    String purl = "pkg:oci/hardened-nginx?repository_url=other.io/path/hardened-nginx&tag=1.25";
    PackageRef ref = new PackageRef(purl);
    Map<String, String> registryMap =
        Map.of("quay.io/hummingbird", "registry.access.redhat.com/hi");

    // When applying the registry map
    PackageRef result = HardenedImageResponseHandler.applyRegistryMap(ref, registryMap);

    // Then the original ref is returned unchanged
    assertEquals(ref.ref(), result.ref());
  }

  // Verifies that applyRegistryMap handles an empty map gracefully.
  @Test
  void testApplyRegistryMapEmptyMap() {
    // Given a PackageRef and an empty registry map
    PackageRef ref = new PackageRef(HARDENED_NGINX_PURL);

    // When applying the empty map
    PackageRef result = HardenedImageResponseHandler.applyRegistryMap(ref, Collections.emptyMap());

    // Then the original ref is returned unchanged
    assertEquals(ref.ref(), result.ref());
  }

  // Verifies that applyRegistryMap handles a null map gracefully.
  @Test
  void testApplyRegistryMapNullMap() {
    PackageRef ref = new PackageRef(HARDENED_NGINX_PURL);
    PackageRef result = HardenedImageResponseHandler.applyRegistryMap(ref, null);
    assertEquals(ref.ref(), result.ref());
  }

  // Verifies that the registry map preserves image tags unchanged.
  @Test
  void testRegistryMapPreservesTag() {
    // Given a PackageRef with a specific tag
    String purl =
        "pkg:oci/hardened-nginx?repository_url=quay.io/hummingbird/hardened-nginx&tag=1.25-alpine";
    PackageRef ref = new PackageRef(purl);
    Map<String, String> registryMap =
        Map.of("quay.io/hummingbird", "registry.access.redhat.com/hi");

    // When applying the registry map
    PackageRef result = HardenedImageResponseHandler.applyRegistryMap(ref, registryMap);

    // Then the tag is preserved
    assertEquals("1.25-alpine", result.purl().getQualifiers().get("tag"));
  }

  // Verifies that the index data is not mutated when registry map is applied.
  @Test
  void testRegistryMapDoesNotMutateCachedIndex() {
    // Given an index with a hardened recommendation and a registry map
    String hardenedPurl =
        "pkg:oci/hardened-nginx?repository_url=quay.io/hummingbird/hardened-nginx&tag=1.25";
    IndexedRecommendation rec =
        IndexedRecommendation.builder()
            .packageName(new PackageRef(hardenedPurl))
            .vulnerabilities(Collections.emptyMap())
            .sourceName("hardened")
            .build();
    provider.getIndex().replaceAll(Map.of("docker.io/library/nginx:1.25", List.of(rec)));
    when(config.registryMap())
        .thenReturn(Map.of("quay.io/hummingbird", "registry.access.redhat.com/hi"));

    // When performing the lookup
    String ociPurl = "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25";
    provider.lookupBySbomId(ociPurl);

    // Then the original index entry is not mutated
    var indexedRec = provider.lookup("docker.io/library/nginx:1.25").get(0);
    assertEquals(
        "quay.io/hummingbird/hardened-nginx",
        indexedRec.packageName().purl().getQualifiers().get("repository_url"),
        "Index data must not be mutated by registry map application");
  }
}
