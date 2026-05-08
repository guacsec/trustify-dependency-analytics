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

package io.github.guacsec.trustifyda.integration.backend.sbom.spdx;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.integration.sbom.spdx.SpdxParser;
import io.github.guacsec.trustifyda.model.DependencyTree;

class SpdxParserTest {

  private static final String TEST_RESOURCES_PATH = "/spdx/";

  /** Verifies that all checksums are extracted from SPDX package entries. */
  @Test
  void testParseHashesFromPackages() throws IOException {
    SpdxParser parser = new SpdxParser();
    try (InputStream input =
        getClass().getResourceAsStream(TEST_RESOURCES_PATH + "sbom-with-hashes.json")) {
      assertNotNull(input, "Test resource not found");

      DependencyTree tree = parser.buildTree(input);
      Map<String, Map<String, String>> hashes = tree.componentHashes();

      assertNotNull(hashes);
      assertEquals(2, hashes.size());

      Map<String, String> dep1Hashes = hashes.get("pkg:maven/com.example/dep1@1.0.0");
      assertNotNull(dep1Hashes);
      assertEquals(1, dep1Hashes.size());
      assertEquals(
          "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
          dep1Hashes.get("SHA256"));

      Map<String, String> dep2Hashes = hashes.get("pkg:maven/com.example/dep2@1.0.0");
      assertNotNull(dep2Hashes);
      assertEquals(2, dep2Hashes.size());
      assertEquals("d41d8cd98f00b204e9800998ecf8427e", dep2Hashes.get("MD5"));
      assertEquals(
          "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
          dep2Hashes.get("SHA256"));

      assertFalse(hashes.containsKey("pkg:maven/com.example/dep3@1.0.0"));
    }
  }

  /** Verifies that parsing a SBOM without checksums produces an empty hash map. */
  @Test
  void testParseHashesFromPackagesWithoutChecksums() throws IOException {
    SpdxParser parser = new SpdxParser();
    try (InputStream input =
        getClass().getResourceAsStream(TEST_RESOURCES_PATH + "empty-sbom.json")) {
      assertNotNull(input, "Test resource not found");

      DependencyTree tree = parser.buildTree(input);
      Map<String, Map<String, String>> hashes = tree.componentHashes();

      assertNotNull(hashes);
      assertTrue(hashes.isEmpty());
    }
  }
}
