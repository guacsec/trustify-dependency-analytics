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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

class JsonUtilsTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void testGetTextValue_withValidKey() {
    ObjectNode node = mapper.createObjectNode();
    node.put("name", "test-value");

    String result = JsonUtils.getTextValue(node, "name");

    assertEquals("test-value", result);
  }

  @Test
  void testGetTextValue_withMissingKey() {
    ObjectNode node = mapper.createObjectNode();
    node.put("name", "test-value");

    String result = JsonUtils.getTextValue(node, "missing");

    assertNull(result);
  }

  @Test
  void testGetTextValue_withNullValue() {
    ObjectNode node = mapper.createObjectNode();
    node.putNull("name");

    String result = JsonUtils.getTextValue(node, "name");

    assertNull(result);
  }

  @Test
  void testGetTextValue_withNullNode() {
    String result = JsonUtils.getTextValue(null, "name");

    assertNull(result);
  }

  @Test
  void testGetTextValue_withEmptyString() {
    ObjectNode node = mapper.createObjectNode();
    node.put("name", "");

    String result = JsonUtils.getTextValue(node, "name");

    assertEquals("", result);
  }

  @Test
  void testGetTextValue_withNumericValue() {
    ObjectNode node = mapper.createObjectNode();
    node.put("count", 123);

    String result = JsonUtils.getTextValue(node, "count");

    assertEquals("123", result);
  }

  @Test
  void testGetTextValue_withBooleanValue() {
    ObjectNode node = mapper.createObjectNode();
    node.put("enabled", true);

    String result = JsonUtils.getTextValue(node, "enabled");

    assertEquals("true", result);
  }

  @Test
  void testGetTextValue_withNestedObject() {
    ObjectNode nested = mapper.createObjectNode();
    nested.put("inner", "value");

    ObjectNode node = mapper.createObjectNode();
    node.set("outer", nested);

    String result = JsonUtils.getTextValue(node, "outer");

    // asText() on an object node returns empty string, not JSON representation
    assertNotNull(result);
    assertEquals("", result);
  }
}
