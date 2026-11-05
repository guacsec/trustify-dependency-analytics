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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.model.v2.SpdxDocument;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.Version;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.config.exception.SpdxValidationException;
import io.github.guacsec.trustifyda.integration.sbom.spdx.SpdxWrapper;

public class SpdxWrapperTest {

  private static final String VALIDATION_ERRORS_BASE = "spdx/validation-errors/";
  private static final String CASE_ONLY_LICENSE_REFS =
      VALIDATION_ERRORS_BASE + "spdx-2.3-case-insensitive-license-refs.json";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  /**
   * Verifies that merging case-only license references preserves packages, graph edges, and hashes.
   */
  @Test
  void testCaseOnlyLicenseReferencesPreservePackageGraph() {
    // Given a document whose two dependencies use different case variants of one license
    var root = new PackageRef("pkg:maven/org/root@1.0");
    var direct = new PackageRef("pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final");
    var transitive =
        new PackageRef("pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2");

    // When parsing the reproducer through the real SPDX store
    var wrapper = new SpdxWrapper(stream(CASE_ONLY_LICENSE_REFS));

    // Then both distinct packages and the original dependency chain and checksum survive
    assertEquals(Set.of(direct), wrapper.getStartFromPackages());
    assertEquals(
        Map.of(root, Set.of(direct), direct, Set.of(transitive)), wrapper.getRelationships());
    assertEquals(
        Map.of(
            "pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final",
            Map.of("SHA256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
        wrapper.getComponentHashes());
  }

  /**
   * Verifies one canonical definition and consistent package declarations without losing metadata.
   */
  @Test
  void testCaseOnlyLicenseReferencesUseCanonicalDefinition() throws Exception {
    // Given equivalent definitions with additional matching metadata
    var sbom = caseOnlyLicenseRefs();
    for (var definition : sbom.withArray("hasExtractedLicensingInfos")) {
      ((ObjectNode) definition).put("comment", "shared metadata");
      ((ObjectNode) definition).putArray("seeAlsos").add("https://example.com/license");
    }

    // When parsing through the actual library
    var document = parsedDocument(new SpdxWrapper(jsonStream(sbom)));

    // Then both declarations point to the retained definition, including its original metadata
    var definitions = document.getExtractedLicenseInfos();
    assertEquals(1, definitions.size());
    var license = definitions.iterator().next();
    assertEquals("LicenseRef-MIT-License", license.getLicenseId());
    assertEquals("MIT License", license.getName());
    assertEquals("NOASSERTION", license.getExtractedText());
    assertEquals("shared metadata", license.getComment());
    assertEquals(List.of("https://example.com/license"), List.copyOf(license.getSeeAlso()));
    for (var id : List.of("SPDXRef-Direct", "SPDXRef-Transitive")) {
      var pkg =
          new SpdxPackage(document.getModelStore(), document.getDocumentUri(), id, null, false);
      assertEquals("LicenseRef-MIT-License", pkg.getLicenseDeclared().toString());
      assertEquals("LicenseRef-MIT-License", pkg.getLicenseConcluded().toString());
    }
  }

  /**
   * Verifies that materially different text or metadata is never discarded in a case-only merge.
   */
  @ParameterizedTest
  @ValueSource(strings = {"extractedText", "name", "comment", "seeAlsos", "missingName"})
  void testConflictingCaseOnlyLicenseDefinitionsAreRejected(String difference) throws Exception {
    // Given case-colliding definitions with one material difference
    var sbom = caseOnlyLicenseRefs();
    var second = (ObjectNode) sbom.withArray("hasExtractedLicensingInfos").get(1);
    switch (difference) {
      case "extractedText" -> second.put("extractedText", "Different license terms");
      case "name" -> second.put("name", "A different license");
      case "comment" -> second.put("comment", "Additional terms apply");
      case "seeAlsos" -> second.putArray("seeAlsos").add("https://example.com/other-license");
      case "missingName" -> second.remove("name");
      default -> throw new IllegalArgumentException(difference);
    }

    // When attempting to parse the conflicting definitions
    var error =
        assertThrows(SpdxValidationException.class, () -> new SpdxWrapper(jsonStream(sbom)));

    // Then the validation error identifies the conflicting pair rather than a duplicate URI
    assertTrue(error.getDetails().contains("Conflicting SPDX LicenseRef definitions"));
    assertTrue(error.getDetails().contains("LicenseRef-MIT-License"));
    assertTrue(error.getDetails().contains("LicenseRef-MIT-license"));
  }

  /**
   * Verifies complete-token rewriting in scalar expressions and package, file, and snippet arrays.
   */
  @Test
  void testLocalLicenseReferencesAreRewrittenInExpressions() throws Exception {
    // Given local references in every SPDX 2.3 licensing field, including compound expressions
    var sbom = caseOnlyLicenseRefs();
    var direct = (ObjectNode) sbom.withArray("packages").get(1);
    direct.put("licenseDeclared", "(LicenseRef-MIT-license OR MIT) AND Apache-2.0");
    direct.putArray("licenseInfoFromFiles").add("LicenseRef-MIT-license");
    var file = sbom.putArray("files").addObject();
    file.put("SPDXID", "SPDXRef-File");
    file.put("fileName", "example.txt");
    file.put("licenseConcluded", "LicenseRef-MIT-license");
    file.putArray("licenseInfoInFiles").add("LicenseRef-MIT-license");
    var snippet = sbom.putArray("snippets").addObject();
    snippet.put("SPDXID", "SPDXRef-Snippet");
    snippet.put("snippetFromFile", "SPDXRef-File");
    snippet.put("licenseConcluded", "LicenseRef-MIT-license");
    snippet.putArray("licenseInfoInSnippets").add("LicenseRef-MIT-license");
    var range = snippet.putArray("ranges").addObject();
    range.putObject("startPointer").put("reference", "SPDXRef-File").put("offset", 0);
    range.putObject("endPointer").put("reference", "SPDXRef-File").put("offset", 1);

    // When normalizing and deserializing the document
    var normalized = normalizedJson(sbom);

    // Then all uses point to the surviving definition, without changing expression syntax
    assertEquals(
        "(LicenseRef-MIT-License OR MIT) AND Apache-2.0",
        normalized.at("/packages/1/licenseDeclared").asText());
    for (var pointer :
        List.of(
            "/packages/1/licenseInfoFromFiles/0",
            "/packages/2/licenseDeclared",
            "/packages/2/licenseConcluded",
            "/files/0/licenseConcluded",
            "/files/0/licenseInfoInFiles/0",
            "/snippets/0/licenseConcluded",
            "/snippets/0/licenseInfoInSnippets/0")) {
      assertEquals("LicenseRef-MIT-License", normalized.at(pointer).asText(), pointer);
    }
  }

  /**
   * Verifies that longer IDs, external references, and literal text keep their original meaning.
   */
  @Test
  void testNonLocalAndUnrelatedValuesAreNotRewritten() throws Exception {
    // Given a longer independent license ID, an external license, and literal occurrences
    var sbom = caseOnlyLicenseRefs();
    var definitions = sbom.withArray("hasExtractedLicensingInfos");
    for (var definition : definitions) {
      ((ObjectNode) definition).put("extractedText", "Literal LicenseRef-MIT-license");
    }
    definitions
        .addObject()
        .put("licenseId", "LicenseRef-MIT-license-extra")
        .put("extractedText", "Independent license");
    sbom.put("comment", "Literal LicenseRef-MIT-license");
    var external = sbom.putArray("externalDocumentRefs").addObject();
    external.put("externalDocumentId", "DocumentRef-other");
    external.put("spdxDocument", "https://example.com/other-document");
    external
        .putObject("checksum")
        .put("algorithm", "SHA1")
        .put("checksumValue", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    var direct = (ObjectNode) sbom.withArray("packages").get(1);
    direct.put("name", "Literal LicenseRef-MIT-license");
    direct.put(
        "licenseDeclared",
        "LicenseRef-MIT-license AND LicenseRef-MIT-license-extra OR"
            + " DocumentRef-other:LicenseRef-MIT-license");

    // When normalizing and parsing the document
    var normalized = normalizedJson(sbom);

    // Then only the complete local reference belonging to the collision group changes
    assertEquals(
        "LicenseRef-MIT-License AND LicenseRef-MIT-license-extra OR"
            + " DocumentRef-other:LicenseRef-MIT-license",
        normalized.at("/packages/1/licenseDeclared").asText());
    assertEquals("Literal LicenseRef-MIT-license", normalized.path("comment").asText());
    assertEquals("Literal LicenseRef-MIT-license", normalized.at("/packages/1/name").asText());
    assertEquals(
        "Literal LicenseRef-MIT-license",
        normalized.at("/hasExtractedLicensingInfos/0/extractedText").asText());
    assertEquals(
        "LicenseRef-MIT-license-extra",
        normalized.at("/hasExtractedLicensingInfos/1/licenseId").asText());
  }

  /** Verifies that locale-specific case folding cannot split an otherwise equivalent ID pair. */
  @Test
  void testCaseOnlyLicenseReferencesAreLocaleIndependent() throws Exception {
    // Given a lowercase variant and a Turkish default locale
    var original = Locale.getDefault();
    var sbom = caseOnlyLicenseRefs();
    ((ObjectNode) sbom.withArray("hasExtractedLicensingInfos").get(1))
        .put("licenseId", "LicenseRef-mit-license");
    ((ObjectNode) sbom.withArray("packages").get(2))
        .put("licenseDeclared", "LicenseRef-mit-license")
        .put("licenseConcluded", "LicenseRef-mit-license");
    try {
      Locale.setDefault(Locale.forLanguageTag("tr-TR"));
      // When parsing and normalizing under that locale
      var normalized = normalizedJson(sbom);
      // Then the canonical spelling is still the first definition's ID
      assertEquals(1, normalized.withArray("hasExtractedLicensingInfos").size());
      assertEquals("LicenseRef-MIT-License", normalized.at("/packages/2/licenseDeclared").asText());
    } finally {
      Locale.setDefault(original);
    }
  }

  // Verifies that absent licensing data and non-colliding definitions still parse without merging.
  @ParameterizedTest
  @ValueSource(strings = {"missing", "empty", "single", "distinct"})
  void testMissingAndNonCollidingLicenseDefinitionsRemainSupported(String variant)
      throws Exception {
    // Given a document without a collision
    var sbom = nonCollidingLicenseRefs(variant);

    // When parsing the document
    var wrapper = new SpdxWrapper(jsonStream(sbom));

    // Then package discovery is unchanged and unrelated definitions are not removed
    assertEquals(
        Set.of(new PackageRef("pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final")),
        wrapper.getStartFromPackages());
    assertEquals(
        variant.equals("distinct") ? 2 : variant.equals("single") ? 1 : 0,
        parsedDocument(wrapper).getExtractedLicenseInfos().size());
  }

  // Verifies the common path preserves the original bytes without allocating a JSON object tree.
  @ParameterizedTest
  @ValueSource(strings = {"missing", "empty", "single", "distinct"})
  void testNonCollidingDocumentIsReturnedUnchangedWithoutJsonTree(String variant) throws Exception {
    // Given a non-colliding document with whitespace that serialization would change
    byte[] content =
        (" \n" + MAPPER.writeValueAsString(nonCollidingLicenseRefs(variant)) + "\n ")
            .getBytes(StandardCharsets.UTF_8);
    var field = SpdxWrapper.class.getDeclaredField("MAPPER");
    field.setAccessible(true);
    var mapper = (ObjectMapper) field.get(null);
    var originalFactory = mapper.getNodeFactory();
    var objectNodes = new AtomicInteger();
    mapper.setNodeFactory(
        new JsonNodeFactory() {
          @Override
          public ObjectNode objectNode() {
            objectNodes.incrementAndGet();
            return super.objectNode();
          }
        });

    // When normalizing through the production boundary with allocation tracking
    try (var normalized = normalize(new ByteArrayInputStream(content))) {
      // Then both the original encoding and the tree-free memory contract are preserved
      assertArrayEquals(content, normalized.readAllBytes());
      assertEquals(0, objectNodes.get(), "Non-colliding documents must not allocate a JSON tree");
    } finally {
      mapper.setNodeFactory(originalFactory);
    }
  }

  // Verifies that definitions preceding the SPDX 2.3 version still merge.
  @Test
  void testLicenseReferenceNormalizationWithVersionLast() throws Exception {
    // Given colliding definitions before the root version field
    var sbom = caseOnlyLicenseRefs();
    sbom.remove("spdxVersion");
    sbom.put("spdxVersion", "SPDX-2.3");
    var expected = sbom.deepCopy();
    expected.withArray("hasExtractedLicensingInfos").remove(1);
    ((ObjectNode) expected.withArray("packages").get(2))
        .put("licenseDeclared", "LicenseRef-MIT-License")
        .put("licenseConcluded", "LicenseRef-MIT-License");

    // When normalizing the reordered document
    try (var normalized = normalize(jsonStream(sbom))) {
      // Then the definitions and local references use the first spelling
      assertEquals(expected, MAPPER.readTree(normalized));
    }
  }

  // Verifies that a later version field prevents normalization outside SPDX 2.3.
  @ParameterizedTest
  @ValueSource(strings = {"SPDX-2.2", "SPDX-3.0"})
  void testOtherVersionsAreReturnedUnchanged(String version) throws Exception {
    // Given collisions followed by a version outside the normalizer's scope
    var sbom = caseOnlyLicenseRefs();
    sbom.remove("spdxVersion");
    sbom.put("spdxVersion", version);
    byte[] content = MAPPER.writeValueAsBytes(sbom);

    // When normalizing the document
    try (var normalized = normalize(new ByteArrayInputStream(content))) {
      // Then neither the definitions nor their references nor formatting change
      assertArrayEquals(content, normalized.readAllBytes());
    }
  }

  /** Verifies malformed JSON still produces an SPDX validation exception. */
  @Test
  void testMalformedJsonIsRejected() {
    assertThrows(
        SpdxValidationException.class,
        () -> new SpdxWrapper(new ByteArrayInputStream("{".getBytes(StandardCharsets.UTF_8))));
  }

  private static ObjectNode caseOnlyLicenseRefs() throws IOException {
    try (var input = stream(CASE_ONLY_LICENSE_REFS)) {
      return (ObjectNode) MAPPER.readTree(input);
    }
  }

  private static ObjectNode nonCollidingLicenseRefs(String variant) throws IOException {
    var sbom = caseOnlyLicenseRefs();
    var definitions = sbom.withArray("hasExtractedLicensingInfos");
    switch (variant) {
      case "missing" -> sbom.remove("hasExtractedLicensingInfos");
      case "empty" -> definitions.removeAll();
      case "single" -> definitions.remove(1);
      case "distinct" -> ((ObjectNode) definitions.get(1)).put("licenseId", "LicenseRef-Other");
      default -> throw new IllegalArgumentException(variant);
    }
    for (var pkg : sbom.withArray("packages")) {
      ((ObjectNode) pkg)
          .put("licenseDeclared", "NOASSERTION")
          .put("licenseConcluded", "NOASSERTION");
    }
    return sbom;
  }

  private static InputStream jsonStream(ObjectNode sbom) throws IOException {
    return new ByteArrayInputStream(MAPPER.writeValueAsBytes(sbom));
  }

  private static SpdxDocument parsedDocument(SpdxWrapper wrapper)
      throws ReflectiveOperationException {
    var field = SpdxWrapper.class.getDeclaredField("doc");
    field.setAccessible(true);
    return (SpdxDocument) field.get(wrapper);
  }

  // Inspect the compatibility boundary as well as parsing: the library can otherwise mask stale
  // reference spellings through its own case-insensitive lookups. Keep this access test-only.
  private static ObjectNode normalizedJson(ObjectNode sbom) throws Exception {
    new SpdxWrapper(jsonStream(sbom));
    try (var input = normalize(jsonStream(sbom))) {
      return (ObjectNode) MAPPER.readTree(input);
    }
  }

  private static InputStream normalize(InputStream input) throws ReflectiveOperationException {
    var normalizer =
        SpdxWrapper.class.getDeclaredMethod("normalizeLicenseReferences", InputStream.class);
    normalizer.setAccessible(true);
    return (InputStream) normalizer.invoke(null, input);
  }

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
