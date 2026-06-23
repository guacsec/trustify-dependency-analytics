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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
                "docker.io/library/nginx:1.25", nginxRec,
                "docker.io/library/nginx:1.25-alpine", nginxRec))
        .when(spyProvider)
        .fetchAndParseData(anyString());

    // When the refresh runs
    spyProvider.refresh();

    // Then the lock was acquired and the index is populated
    verify(lock).tryAcquire(eq(LOCK_KEY), any());
    assertEquals(2, spyProvider.getIndex().size());
    assertNotNull(spyProvider.lookup("docker.io/library/nginx:1.25"));
    assertNotNull(spyProvider.lookup("docker.io/library/nginx:1.25-alpine"));
    assertEquals(
        normalized(HARDENED_NGINX_PURL),
        spyProvider.lookup("docker.io/library/nginx:1.25").packageName().ref());
    assertEquals("hardened", spyProvider.lookup("docker.io/library/nginx:1.25").sourceName());
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
    Map<String, IndexedRecommendation> result = responseHandler.parseAndInvertMapping(json);

    // Then each base image maps to its hardened recommendation with an OCI PURL
    assertEquals(3, result.size());
    var pythonRec = result.get("docker.io/library/python:3.12");
    assertNotNull(pythonRec);
    assertEquals("oci", pythonRec.packageName().purl().getType());
    assertEquals("hardened-python", pythonRec.packageName().purl().getName());
    assertEquals(
        pythonRec.packageName().ref(),
        result.get("docker.io/library/python:3.12-slim").packageName().ref());

    var nodeRec = result.get("docker.io/library/node:20");
    assertNotNull(nodeRec);
    assertEquals("oci", nodeRec.packageName().purl().getType());
    assertEquals("hardened-node", nodeRec.packageName().purl().getName());
    assertEquals("hardened", nodeRec.sourceName());
  }

  // Verifies that the provider returns empty results when the Hummingbird URL is not configured.
  @Test
  void testDisabledWhenUrlNotConfigured() {
    // Given no Hummingbird URL configured
    when(config.url()).thenReturn(Optional.empty());

    // When the refresh runs
    provider.refresh();

    // Then no lock is acquired and lookup returns null
    verify(lock, never()).tryAcquire(anyString(), any());
    assertNull(provider.lookup("docker.io/library/nginx:1.25"));
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
    doReturn(Map.of("base:1.0", rec)).when(spyProvider).fetchAndParseData(anyString());

    // When refresh completes successfully
    spyProvider.refresh();

    // Then the lock is released and the index is populated
    verify(lock).release(LOCK_KEY);
    assertEquals(1, spyProvider.getIndex().size());
    assertNotNull(spyProvider.lookup("base:1.0"));
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
    Map<String, IndexedRecommendation> result = responseHandler.parseAndInvertMapping(json);

    // Then the mapping is correctly inverted with an OCI PURL
    assertEquals(1, result.size());
    var rec = result.get("docker.io/library/alpine:3.19");
    assertNotNull(rec);
    assertEquals("oci", rec.packageName().purl().getType());
    assertEquals("hardened-alpine", rec.packageName().purl().getName());
  }

  // Verifies that parsing returns empty index for responses with no images.
  @Test
  void testParseEmptyResponse() throws Exception {
    // Given an empty Hummingbird response
    String json = "{\"images\": {}}";

    // When parsing
    Map<String, IndexedRecommendation> result = responseHandler.parseAndInvertMapping(json);

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
    Map<String, IndexedRecommendation> result = responseHandler.parseAndInvertMapping(json);

    // Then only the valid entry with compare_to is indexed
    assertEquals(1, result.size());
    assertNotNull(result.get("base:3.0"));
    assertNull(result.get("base:1.0"));
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
    doReturn(Map.of("base:1.0", rec)).when(spyProvider).fetchAndParseData(anyString());
    spyProvider.refresh();
    assertEquals(1, spyProvider.getIndex().size());

    // Second refresh: Hummingbird returns empty data
    doReturn(Collections.<String, IndexedRecommendation>emptyMap())
        .when(spyProvider)
        .fetchAndParseData(anyString());
    spyProvider.refresh();

    // Then the existing index is preserved
    assertEquals(1, spyProvider.getIndex().size());
    assertNotNull(spyProvider.lookup("base:1.0"));
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
    doReturn(Map.of("base:1.0", rec)).when(spyProvider).fetchAndParseData(anyString());
    spyProvider.refresh();
    assertEquals(1, spyProvider.getIndex().size());

    // Second refresh: fetchAndParseData throws (simulating HTTP failure)
    doThrow(new RuntimeException("Connection refused"))
        .when(spyProvider)
        .fetchAndParseData(anyString());
    spyProvider.refresh();

    // Then the existing index is preserved and the lock is released
    assertEquals(1, spyProvider.getIndex().size());
    assertNotNull(spyProvider.lookup("base:1.0"));
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
    doReturn(Map.of("base:1.0", rec)).when(spyProvider).fetchAndParseData(anyString());

    // Lock release throws (simulating Redis connection failure)
    doThrow(new RuntimeException("Redis connection lost")).when(lock).release(LOCK_KEY);

    // When refresh runs — should not throw despite lock release failure
    spyProvider.refresh();

    // Then the index is still populated (refresh completed before the finally block)
    assertEquals(1, spyProvider.getIndex().size());
    assertNotNull(spyProvider.lookup("base:1.0"));
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
    provider.getIndex().replaceAll(Map.of("docker.io/library/nginx:1.25", rec));

    // When looking up by OCI PURL with matching repository_url and tag
    String ociPurl =
        "pkg:oci/nginx@sha256:def456?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25";
    var result = provider.lookupBySbomId(ociPurl);

    // Then the recommendation is returned
    assertEquals(1, result.size());
    var entry = result.entrySet().iterator().next();
    assertEquals(normalized(HARDENED_NGINX_PURL), entry.getValue().packageName().ref());
    assertEquals("hardened", entry.getValue().sourceName());
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
}
