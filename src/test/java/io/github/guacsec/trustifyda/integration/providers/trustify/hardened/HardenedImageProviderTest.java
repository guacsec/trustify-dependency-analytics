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
  private static final String HARDENED_PYTHON_PURL =
      "pkg:oci/hardened-python@sha256:def456?repository_url=registry.example.com/hardened-python&tag=3.12";
  private static final String HARDENED_NODE_PURL =
      "pkg:oci/hardened-node@sha256:ghi789?repository_url=registry.example.com/hardened-node&tag=20";
  private static final String HARDENED_ALPINE_PURL =
      "pkg:oci/hardened-alpine@sha256:jkl012?repository_url=registry.example.com/hardened-alpine&tag=3.19";

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

  /// Verifies that the periodic refresh acquires the lock, fetches data, and populates the index.
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

  /// Verifies that a second instance skips refresh when the lock is already held.
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

  /// Verifies that Hummingbird response parsing correctly inverts the compare_to mapping.
  @Test
  void testParseAndInvertMapping() throws Exception {
    // Given a Hummingbird response with multiple hardened images
    String json =
        "[{\"image_ref\": \""
            + HARDENED_PYTHON_PURL
            + "\","
            + "\"compare_to\": [\"docker.io/library/python:3.12\","
            + " \"docker.io/library/python:3.12-slim\"]},"
            + "{\"image_ref\": \""
            + HARDENED_NODE_PURL
            + "\","
            + "\"compare_to\": [\"docker.io/library/node:20\"]}]";

    // When parsing and inverting the mapping
    Map<String, IndexedRecommendation> result = responseHandler.parseAndInvertMapping(json);

    // Then each base image maps to its hardened recommendation
    assertEquals(3, result.size());
    assertEquals(
        normalized(HARDENED_PYTHON_PURL),
        result.get("docker.io/library/python:3.12").packageName().ref());
    assertEquals(
        normalized(HARDENED_PYTHON_PURL),
        result.get("docker.io/library/python:3.12-slim").packageName().ref());
    assertEquals(
        normalized(HARDENED_NODE_PURL),
        result.get("docker.io/library/node:20").packageName().ref());
    assertEquals("hardened", result.get("docker.io/library/node:20").sourceName());
  }

  /// Verifies that the provider returns empty results when the Hummingbird URL is not configured.
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

  /// Verifies that the lock is released after a successful data load.
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

  /// Verifies that parsing handles a nested object format with an "images" key.
  @Test
  void testParseNestedObjectFormat() throws Exception {
    // Given a Hummingbird response using nested object format
    String json =
        "{\"images\": [{\"image_ref\": \""
            + HARDENED_ALPINE_PURL
            + "\","
            + "\"compare_to\": [\"docker.io/library/alpine:3.19\"]}]}";

    // When parsing
    Map<String, IndexedRecommendation> result = responseHandler.parseAndInvertMapping(json);

    // Then the mapping is correctly inverted
    assertEquals(1, result.size());
    assertEquals(
        normalized(HARDENED_ALPINE_PURL),
        result.get("docker.io/library/alpine:3.19").packageName().ref());
  }

  /// Verifies that parsing returns empty index for responses with no images.
  @Test
  void testParseEmptyResponse() throws Exception {
    // Given an empty Hummingbird response
    String json = "{\"images\": []}";

    // When parsing
    Map<String, IndexedRecommendation> result = responseHandler.parseAndInvertMapping(json);

    // Then the result is empty
    assertTrue(result.isEmpty());
  }

  /// Verifies that entries with blank image_ref or invalid PURLs are skipped.
  @Test
  void testParseSkipsInvalidEntries() throws Exception {
    // Given a response with some invalid entries
    String json =
        "[{\"image_ref\": \"\", \"compare_to\": [\"base:1.0\"]},"
            + "{\"image_ref\": \"not-a-valid-purl\", \"compare_to\": [\"base:2.0\"]},"
            + "{\"image_ref\": \""
            + HARDENED_NGINX_PURL
            + "\", \"compare_to\": [\"base:3.0\"]},"
            + "{\"image_ref\": \""
            + HARDENED_PYTHON_PURL
            + "\"}]";

    // When parsing
    Map<String, IndexedRecommendation> result = responseHandler.parseAndInvertMapping(json);

    // Then only the valid entry with compare_to is indexed
    assertEquals(1, result.size());
    assertNotNull(result.get("base:3.0"));
    assertNull(result.get("base:1.0"));
    assertNull(result.get("base:2.0"));
  }

  /// Verifies that a populated index is preserved when Hummingbird returns empty data.
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

  /// Verifies that a populated index is preserved when fetchAndParseData throws an exception.
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

  /// Verifies that lock release failure does not propagate and the index remains intact.
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
}
