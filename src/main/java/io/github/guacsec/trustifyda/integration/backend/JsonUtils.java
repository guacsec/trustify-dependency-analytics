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

package io.github.guacsec.trustifyda.integration.backend;

import com.fasterxml.jackson.databind.JsonNode;

import io.quarkus.runtime.annotations.RegisterForReflection;

/** Utility class for JSON operations. */
@RegisterForReflection
public class JsonUtils {

  private JsonUtils() {}

  /**
   * Extracts a text value from a JSON node with null-safety.
   *
   * @param node the JSON node
   * @param key the key to extract
   * @return the text value, or null if the key doesn't exist or is null
   */
  public static String getTextValue(JsonNode node, String key) {
    if (node != null && node.has(key) && node.hasNonNull(key)) {
      return node.get(key).asText();
    }
    return null;
  }

  /**
   * Extracts a boolean value from a JSON node with null-safety.
   *
   * @param node the JSON node
   * @param key the key to extract
   * @return the boolean value, or false if the key doesn't exist or is null
   */
  public static Boolean getBooleanValue(JsonNode node, String key) {
    if (node != null && node.has(key) && node.hasNonNull(key)) {
      return node.get(key).asBoolean();
    }
    return null;
  }
}
