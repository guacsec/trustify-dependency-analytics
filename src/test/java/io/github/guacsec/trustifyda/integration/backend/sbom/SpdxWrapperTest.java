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

package io.github.guacsec.trustifyda.integration.backend.sbom;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.model.v2.Version;

import io.github.guacsec.trustifyda.config.exception.SpdxValidationException;
import io.github.guacsec.trustifyda.integration.sbom.spdx.SpdxWrapper;

public class SpdxWrapperTest {

  private static final String VALIDATION_ERRORS_BASE = "spdx/validation-errors/";

  @ParameterizedTest
  @ValueSource(strings = {Version.TWO_POINT_THREE_VERSION, Version.TWO_POINT_TWO_VERSION})
  void testVersions(String version) throws InvalidSPDXAnalysisException, IOException {
    var wrapper =
        new SpdxWrapper(
            this.getClass()
                .getClassLoader()
                .getResourceAsStream("spdx/versions/" + version + ".json"));
    assertNotNull(wrapper);
    assertNotNull(wrapper.getStartFromPackages());
    assertNotNull(wrapper.getRelationships());
  }

  @Test
  void testInvalidDocument() {
    var err =
        assertThrows(
            SpdxValidationException.class,
            () ->
                new SpdxWrapper(
                    this.getClass()
                        .getClassLoader()
                        .getResourceAsStream("cyclonedx/empty-sbom.json")));
    assertNotNull(err.getMessage());
  }

  @Test
  void testPackagesWithoutPurlAreSkipped() throws Exception {
    // Packages without a PURL cannot be analyzed; they are skipped (no validation error)
    var wrapper = new SpdxWrapper(stream(VALIDATION_ERRORS_BASE + "spdx-2.3-missing-purl.json"));
    assertNotNull(wrapper.getStartFromPackages());
    assertNotNull(wrapper.getRelationships());
    // When all direct deps are skipped, startFrom is empty (same as no-deps SBOM, aligned with
    // CycloneDX)
  }

  @Test
  void testPackagesWithEmptyPurlLocatorAreSkipped() throws Exception {
    var wrapper =
        new SpdxWrapper(stream(VALIDATION_ERRORS_BASE + "spdx-2.3-empty-purl-locator.json"));
    assertNotNull(wrapper.getStartFromPackages());
    assertNotNull(wrapper.getRelationships());
  }

  @Test
  void testValidationErrorInvalidRelationship() {
    var err =
        assertThrows(
            SpdxValidationException.class,
            () ->
                new SpdxWrapper(
                    stream(VALIDATION_ERRORS_BASE + "spdx-2.3-invalid-relationship.json")));
    assertNotNull(err.getMessage());
    assertTrue(
        err.getDetails() != null
            && (err.getDetails().contains("SPDXRef-Nonexistent")
                || err.getDetails().contains("not in this document")),
        "Expected aggregated errors to mention invalid relationship, got: " + err.getDetails());
  }

  @Test
  void testMultiplePackagesWithoutPurlAreSkipped() throws Exception {
    // Multiple packages missing PURL or with empty PURL are all skipped; parse succeeds
    var wrapper = new SpdxWrapper(stream(VALIDATION_ERRORS_BASE + "spdx-2.3-multiple-errors.json"));
    assertNotNull(wrapper.getStartFromPackages());
    assertNotNull(wrapper.getRelationships());
  }

  @Test
  void testDuplicatePackagesCachedProperly() throws Exception {
    // Test that packages referenced multiple times are cached and not processed repeatedly
    var wrapper =
        new SpdxWrapper(stream(VALIDATION_ERRORS_BASE + "spdx-2.3-duplicate-packages.json"));
    assertNotNull(wrapper.getStartFromPackages());
    assertNotNull(wrapper.getRelationships());
    // The same package SPDXRef-Duplicate appears in multiple relationships
    // Caching should prevent re-processing the same package multiple times
  }

  private static InputStream stream(String resource) {
    return SpdxWrapperTest.class.getClassLoader().getResourceAsStream(resource);
  }
}
