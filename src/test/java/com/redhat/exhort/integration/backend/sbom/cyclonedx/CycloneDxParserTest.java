/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
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

package com.redhat.exhort.integration.backend.sbom.cyclonedx;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.config.exception.CycloneDXValidationException;
import com.redhat.exhort.integration.sbom.cyclonedx.CycloneDxParser;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.DirectDependency;

class CycloneDxParserTest {

  private static final String TEST_RESOURCES_PATH = "/cyclonedx/";

  @Test
  void testParseValidSbom() throws IOException {
    CycloneDxParser parser = new CycloneDxParser();
    try (InputStream input =
        getClass().getResourceAsStream(TEST_RESOURCES_PATH + "valid-1.6.json")) {
      assertNotNull(input, "Test resource not found");

      DependencyTree tree = parser.buildTree(input);
      Map<PackageRef, DirectDependency> dependencies = tree.dependencies();

      // Verify direct dependencies
      PackageRef dep1 = new PackageRef("pkg:maven/com.example/dep1@1.0.0");
      PackageRef dep2 = new PackageRef("pkg:maven/com.example/dep2@1.0.0");
      PackageRef transitive = new PackageRef("pkg:maven/com.example/transitive@1.0.0");

      assertTrue(dependencies.containsKey(dep1));
      assertTrue(dependencies.containsKey(dep2));

      // Verify transitive dependencies
      DirectDependency dep1Dependency = dependencies.get(dep1);
      Set<PackageRef> dep1Transitive = dep1Dependency.transitive();
      assertEquals(1, dep1Transitive.size());
      assertTrue(dep1Transitive.contains(transitive));

      // Verify dep2 has no transitive dependencies
      DirectDependency dep2Dependency = dependencies.get(dep2);
      assertTrue(dep2Dependency.transitive().isEmpty());
    }
  }

  @Test
  void testParseSbomWithUnknownDependencies() throws IOException {
    CycloneDxParser parser = new CycloneDxParser();
    try (InputStream input =
        getClass().getResourceAsStream(TEST_RESOURCES_PATH + "unknown-deps.json")) {
      assertNotNull(input, "Test resource not found");

      DependencyTree tree = parser.buildTree(input);
      Map<PackageRef, DirectDependency> dependencies = tree.dependencies();

      PackageRef known = new PackageRef("pkg:maven/com.example/known@1.0.0");
      PackageRef unknown = new PackageRef("pkg:maven/com.example/unknown@1.0.0");

      // Verify both known and unknown dependencies are present
      assertTrue(dependencies.containsKey(known));
      assertTrue(dependencies.containsKey(unknown));

      // Verify unknown dependency has no transitive dependencies
      DirectDependency unknownDependency = dependencies.get(unknown);
      assertTrue(unknownDependency.transitive().isEmpty());
    }
  }

  @Test
  void testParseInvalidSbom() throws IOException {
    CycloneDxParser parser = new CycloneDxParser();
    try (InputStream input =
        getClass().getResourceAsStream(TEST_RESOURCES_PATH + "invalid-sbom.json")) {
      assertNotNull(input, "Test resource not found");
      var exception =
          assertThrows(CycloneDXValidationException.class, () -> parser.buildTree(input));
      assertNotNull(exception.getMessage());
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"})
  void testSupportedVersions(String version) throws IOException {
    String resourcePath = TEST_RESOURCES_PATH + "empty-sbom.json";
    CycloneDxParser parser = new CycloneDxParser();
    try (InputStream input = getClass().getResourceAsStream(resourcePath)) {
      assertNotNull(input, "Test resource not found");

      // Read the file content and replace the version
      String content =
          new String(input.readAllBytes(), StandardCharsets.UTF_8)
              .replace("\"specVersion\": \"1.6\"", "\"specVersion\": \"" + version + "\"");

      // Create a new input stream with the modified content
      try (InputStream modifiedInput =
          new java.io.ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8))) {
        DependencyTree tree = parser.buildTree(modifiedInput);
        assertNotNull(tree);
        assertTrue(tree.dependencies().isEmpty());
      }
    }
  }

  @Test
  void testUnsupportedVersion() throws IOException {
    String resourcePath = TEST_RESOURCES_PATH + "empty-sbom.json";
    CycloneDxParser parser = new CycloneDxParser();
    try (InputStream input = getClass().getResourceAsStream(resourcePath)) {
      assertNotNull(input, "Test resource not found");

      String content =
          new String(input.readAllBytes(), StandardCharsets.UTF_8)
              .replace("\"specVersion\" : \"1.6\"", "\"specVersion\": \"2.0\"");

      try (InputStream modifiedInput =
          new java.io.ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8))) {
        CycloneDXValidationException exception =
            assertThrows(CycloneDXValidationException.class, () -> parser.buildTree(modifiedInput));
        assertNotNull(exception.getMessage());
      }
    }
  }
}
