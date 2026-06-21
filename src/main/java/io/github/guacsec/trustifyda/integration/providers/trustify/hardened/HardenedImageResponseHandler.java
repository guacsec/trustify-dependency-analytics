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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Parses Hummingbird JSON responses and inverts the mapping from hardened images to base images.
 * Each base image reference maps to its hardened image recommendation.
 */
@ApplicationScoped
public class HardenedImageResponseHandler {

  private static final Logger LOG = Logger.getLogger(HardenedImageResponseHandler.class);

  private final ObjectMapper objectMapper;

  public HardenedImageResponseHandler(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  /**
   * Parses the Hummingbird JSON response and inverts the mapping. The response contains hardened
   * images with {@code compare_to} arrays listing base images. This method inverts the
   * relationship: each base image reference maps to its hardened image recommendation.
   */
  public Map<String, IndexedRecommendation> parseAndInvertMapping(String json) throws Exception {
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
