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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;

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
   * relationship: each base image reference maps to all its hardened image recommendations.
   */
  public Map<String, List<IndexedRecommendation>> parseAndInvertMapping(String json)
      throws Exception {
    JsonNode root = objectMapper.readTree(json);
    Map<String, List<IndexedRecommendation>> invertedIndex = new HashMap<>();

    JsonNode images = root.path("images");
    if (images.isMissingNode() || !images.isObject()) {
      LOG.warn("Hummingbird response has no images object, returning empty index");
      return Collections.emptyMap();
    }

    var fields = images.fields();
    while (fields.hasNext()) {
      var entry = fields.next();
      String hardenedRef = entry.getKey();
      JsonNode imageNode = entry.getValue();

      if (hardenedRef == null || hardenedRef.isBlank()) {
        continue;
      }

      JsonNode compareTo = imageNode.path("compare_to");
      if (!compareTo.isArray()) {
        continue;
      }

      PackageRef hardenedPackage;
      try {
        hardenedPackage = containerRefToPackageRef(hardenedRef);
      } catch (Exception e) {
        LOG.warnf("Skipping unparseable image ref in Hummingbird response: %s", hardenedRef);
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
          invertedIndex.computeIfAbsent(baseImageRef, k -> new ArrayList<>()).add(recommendation);
        }
      }
    }

    return invertedIndex;
  }

  /**
   * Converts a container image reference (e.g., {@code quay.io/hummingbird/aspnet-runtime:10}) to
   * an OCI Package URL. The full image path becomes the {@code repository_url} qualifier and the
   * tag (if present) becomes the {@code tag} qualifier.
   */
  static PackageRef containerRefToPackageRef(String imageRef) throws Exception {
    String path;
    String tag = null;

    int atIndex = imageRef.indexOf('@');
    if (atIndex >= 0) {
      path = imageRef.substring(0, atIndex);
    } else {
      int colonIndex = imageRef.lastIndexOf(':');
      if (colonIndex > imageRef.lastIndexOf('/')) {
        path = imageRef.substring(0, colonIndex);
        tag = imageRef.substring(colonIndex + 1);
      } else {
        path = imageRef;
      }
    }

    String name = path.substring(path.lastIndexOf('/') + 1);
    String repoUrl = path;

    TreeMap<String, String> qualifiers = new TreeMap<>();
    qualifiers.put("repository_url", repoUrl);
    if (tag != null) {
      qualifiers.put("tag", tag);
    }

    return new PackageRef(new PackageURL("oci", null, name, null, qualifiers, null));
  }
}
