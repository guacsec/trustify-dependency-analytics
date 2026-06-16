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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.model.trustify.HardenedImageIndex;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.SetArgs;
import io.quarkus.redis.datasource.value.ValueCommands;
import io.quarkus.scheduler.Scheduled;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Provider that periodically fetches hardened image compatibility data from the Hummingbird service
 * and maintains a thread-safe in-memory index for lookups. Uses a Redis distributed lock to prevent
 * concurrent refresh across multiple production instances.
 */
@ApplicationScoped
public class HardenedImageProvider {

  private static final Logger LOG = Logger.getLogger(HardenedImageProvider.class);
  private static final String LOCK_KEY = "hardened-image-refresh-lock";

  @Inject HardenedImageRecommendation config;

  private final HardenedImageIndex index = new HardenedImageIndex();
  private final ValueCommands<String, String> lockCommands;
  private final KeyCommands<String> keyCommands;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final String instanceId = UUID.randomUUID().toString();

  public HardenedImageProvider(RedisDataSource ds, ObjectMapper objectMapper) {
    this.lockCommands = ds.value(String.class);
    this.keyCommands = ds.key();
    this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    this.objectMapper = objectMapper;
  }

  /**
   * Periodic refresh job that fetches hardened image data from Hummingbird. Acquires a Redis
   * distributed lock before fetching to prevent concurrent refresh across production replicas.
   */
  @Scheduled(every = "{trustedcontent.recommendation.hardened.refresh-interval}", delayed = "PT0S")
  void refresh() {
    if (config.url().isEmpty() || config.url().get().isBlank()) {
      LOG.warn("Hummingbird URL not configured, hardened image provider is disabled");
      return;
    }

    String url = config.url().get();
    Duration lockTtl = config.lockTtl();

    try {
      lockCommands.set(LOCK_KEY, instanceId, new SetArgs().nx().ex(lockTtl));
      String holder = lockCommands.get(LOCK_KEY);
      if (!instanceId.equals(holder)) {
        LOG.info("Lock held by another instance, skipping hardened image refresh");
        return;
      }

      LOG.info("Acquired refresh lock, fetching hardened image data from Hummingbird");
      Map<String, IndexedRecommendation> newData = fetchAndParseData(url);
      if (newData.isEmpty() && index.size() > 0) {
        LOG.warn(
            "Hummingbird returned empty data, keeping existing index with "
                + index.size()
                + " entries");
      } else {
        index.replaceAll(newData);
        LOG.infof("Hardened image index updated with %d entries", newData.size());
      }
    } catch (Exception e) {
      LOG.errorf(e, "Failed to refresh hardened image data from %s", url);
    } finally {
      try {
        String currentHolder = lockCommands.get(LOCK_KEY);
        if (instanceId.equals(currentHolder)) {
          keyCommands.del(LOCK_KEY);
        }
      } catch (Exception e) {
        LOG.warnf(e, "Failed to release refresh lock");
      }
    }
  }

  /**
   * Looks up a hardened image recommendation for the given base image reference.
   *
   * @param baseImageRef the base image reference to look up
   * @return the recommendation, or {@code null} if none is available
   */
  public IndexedRecommendation lookup(String baseImageRef) {
    return index.get(baseImageRef);
  }

  /** Returns the current index for inspection. */
  public HardenedImageIndex getIndex() {
    return index;
  }

  /**
   * Fetches the Hummingbird report and parses it into an inverted index mapping base image
   * references to hardened image recommendations.
   */
  Map<String, IndexedRecommendation> fetchAndParseData(String url) throws Exception {
    HttpRequest request =
        HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(30)).GET().build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    if (response.statusCode() != 200) {
      throw new RuntimeException(
          "Hummingbird returned HTTP " + response.statusCode() + " for " + url);
    }

    return parseAndInvertMapping(response.body());
  }

  /**
   * Parses the Hummingbird JSON response and inverts the mapping. The response contains hardened
   * images with {@code compare_to} arrays listing base images. This method inverts the
   * relationship: each base image reference maps to its hardened image recommendation.
   */
  Map<String, IndexedRecommendation> parseAndInvertMapping(String json) throws Exception {
    JsonNode root = objectMapper.readTree(json);
    Map<String, IndexedRecommendation> invertedIndex = new HashMap<>();

    JsonNode images = root.isArray() ? root : root.path("images");
    if (images.isMissingNode() || !images.isArray()) {
      LOG.warn("Hummingbird response has no images array, returning empty index");
      return Collections.emptyMap();
    }

    for (JsonNode imageNode : images) {
      String hardenedRef = imageNode.path("image_ref").asText(null);
      if (hardenedRef == null || hardenedRef.isBlank()) {
        continue;
      }

      JsonNode compareTo = imageNode.path("compare_to");
      if (!compareTo.isArray()) {
        continue;
      }

      PackageRef hardenedPackage;
      try {
        hardenedPackage = new PackageRef(hardenedRef);
      } catch (IllegalArgumentException e) {
        LOG.warnf("Skipping invalid PURL in Hummingbird response: %s", hardenedRef);
        continue;
      }
      IndexedRecommendation recommendation =
          IndexedRecommendation.builder()
              .packageName(hardenedPackage)
              .vulnerabilities(Collections.emptyMap())
              .sourceName("hardened")
              .build();

      for (JsonNode baseRef : compareTo) {
        String baseImageRef = baseRef.asText(null);
        if (baseImageRef != null && !baseImageRef.isBlank()) {
          invertedIndex.put(baseImageRef, recommendation);
        }
      }
    }

    return invertedIndex;
  }
}
