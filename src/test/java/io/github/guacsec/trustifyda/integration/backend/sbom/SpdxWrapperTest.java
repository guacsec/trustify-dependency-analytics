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
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
  private static final List<String> LICENSE_REF_PACKAGE_IDS =
      List.of("SPDXRef-Direct", "SPDXRef-Transitive");
  private static final ObjectMapper MAPPER = new ObjectMapper();

  // Verifies that merging case-only license references preserves packages, graph edges, and hashes.
  @ParameterizedTest
  @ValueSource(
      strings = {
        Version.TWO_POINT_ZERO_VERSION,
        Version.TWO_POINT_ONE_VERSION,
        Version.TWO_POINT_TWO_VERSION,
        Version.TWO_POINT_THREE_VERSION
      })
  void testCaseOnlyLicenseReferencesPreservePackageGraph(String version) throws Exception {
    // Given an SPDX 2.x document whose two dependencies use different case variants of one license
    var root = new PackageRef("pkg:maven/org/root@1.0");
    var direct = new PackageRef("pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final");
    var transitive =
        new PackageRef("pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2");

    // When parsing the reproducer through the real SPDX store
    var wrapper = new SpdxWrapper(createJsonStream(loadCaseOnlyLicenseRefs(version)));

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

  // Verifies one canonical definition and consistent package declarations without losing metadata.
  @ParameterizedTest
  @ValueSource(
      strings = {
        Version.TWO_POINT_ZERO_VERSION,
        Version.TWO_POINT_ONE_VERSION,
        Version.TWO_POINT_TWO_VERSION,
        Version.TWO_POINT_THREE_VERSION
      })
  void testCaseOnlyLicenseReferencesUseCanonicalDefinition(String version) throws Exception {
    // Given SPDX 2.x equivalent definitions with additional matching metadata
    var sbom = loadCaseOnlyLicenseRefs(version);
    for (var definition : sbom.withArray("hasExtractedLicensingInfos")) {
      ((ObjectNode) definition).put("comment", "shared metadata");
      ((ObjectNode) definition).putArray("seeAlsos").add("https://example.com/license");
    }

    // When parsing through the actual library
    var document = getParsedDocument(new SpdxWrapper(createJsonStream(sbom)));

    // Then both declarations point to the retained definition, including its original metadata
    var definitions = document.getExtractedLicenseInfos();
    assertEquals(1, definitions.size());
    var license = definitions.iterator().next();
    assertEquals("LicenseRef-MIT-License", license.getLicenseId());
    assertEquals("MIT License", license.getName());
    assertEquals("NOASSERTION", license.getExtractedText());
    assertEquals("shared metadata", license.getComment());
    assertEquals(List.of("https://example.com/license"), List.copyOf(license.getSeeAlso()));
    assertPackagesUseLicense(document, "LicenseRef-MIT-License");
  }

  // Verifies case-only definitions with reordered seeAlsos share one canonical definition.
  @Test
  void testCaseOnlyLicenseReferencesMergeReorderedSeeAlsos() throws Exception {
    // Given equivalent definitions with the same seeAlsos entries in a different order
    var sbom = loadCaseOnlyLicenseRefs();
    var definitions = sbom.withArray("hasExtractedLicensingInfos");
    ((ObjectNode) definitions.get(0))
        .putArray("seeAlsos")
        .add("https://example.com/license-a")
        .add("https://example.com/license-b");
    ((ObjectNode) definitions.get(1))
        .putArray("seeAlsos")
        .add("https://example.com/license-b")
        .add("https://example.com/license-a");

    // When parsing the document through the actual SPDX library
    var document = getParsedDocument(new SpdxWrapper(createJsonStream(sbom)));

    // Then one canonical definition retains both seeAlsos entries
    var licenses = document.getExtractedLicenseInfos();
    assertEquals(1, licenses.size());
    var license = licenses.iterator().next();
    assertEquals("LicenseRef-MIT-License", license.getLicenseId());
    assertEquals(
        Set.of("https://example.com/license-a", "https://example.com/license-b"),
        Set.copyOf(license.getSeeAlso()));
  }

  // Verifies that equivalent absent/default optional metadata merges into one canonical definition.
  @ParameterizedTest
  @ValueSource(
      strings = {
        "nameNoAssertionOnFirst",
        "nameNoAssertionOnSecond",
        "emptySeeAlsosOnFirst",
        "emptySeeAlsosOnSecond"
      })
  void testEquivalentLicenseDefaultsMerge(String variant) throws Exception {
    // Given definitions differing only in how SPDX represents an absent optional value
    var sbom = loadCaseOnlyLicenseRefs();
    var definitions = sbom.withArray("hasExtractedLicensingInfos");
    var first = (ObjectNode) definitions.get(0);
    var second = (ObjectNode) definitions.get(1);
    switch (variant) {
      case "nameNoAssertionOnFirst" -> {
        first.put("name", "NOASSERTION");
        second.remove("name");
      }
      case "nameNoAssertionOnSecond" -> {
        first.remove("name");
        second.put("name", "NOASSERTION");
      }
      case "emptySeeAlsosOnFirst" -> {
        first.putArray("seeAlsos");
        second.remove("seeAlsos");
      }
      case "emptySeeAlsosOnSecond" -> {
        first.remove("seeAlsos");
        second.putArray("seeAlsos");
      }
      default -> throw new IllegalArgumentException(variant);
    }

    // When parsing the document through the actual SPDX library
    var document = getParsedDocument(new SpdxWrapper(createJsonStream(sbom)));

    // Then one canonical definition survives and both package references use its spelling
    var licenses = document.getExtractedLicenseInfos();
    assertEquals(1, licenses.size());
    assertEquals("LicenseRef-MIT-License", licenses.iterator().next().getLicenseId());
    assertPackagesUseLicense(document, "LicenseRef-MIT-License");
  }

  // Verifies that materially different text or metadata is never discarded in a case-only merge.
  @ParameterizedTest
  @MethodSource("supplyConflictingDefinitionsAcrossVersions")
  void testConflictingCaseOnlyLicenseDefinitionsAreRejected(String version, String difference)
      throws Exception {
    // Given SPDX 2.x case-colliding definitions with one material difference
    var sbom = loadCaseOnlyLicenseRefs(version);
    var definitions = sbom.withArray("hasExtractedLicensingInfos");
    var first = (ObjectNode) definitions.get(0);
    var second = (ObjectNode) definitions.get(1);
    switch (difference) {
      case "extractedText" -> second.put("extractedText", "Different license terms");
      case "name" -> second.put("name", "A different license");
      case "comment" -> second.put("comment", "Additional terms apply");
      case "seeAlsos" -> second.putArray("seeAlsos").add("https://example.com/other-license");
      case "missingName" -> second.remove("name");
      case "noAssertionName" -> second.put("name", "NOASSERTION");
      case "emptySeeAlsos" -> {
        first.putArray("seeAlsos").add("https://example.com/license");
        second.putArray("seeAlsos");
      }
      default -> throw new IllegalArgumentException(difference);
    }

    // When attempting to parse the conflicting definitions
    var error =
        assertThrows(SpdxValidationException.class, () -> new SpdxWrapper(createJsonStream(sbom)));

    // Then the validation error identifies the conflicting pair rather than a duplicate URI
    assertTrue(error.getDetails().contains("Conflicting SPDX LicenseRef definitions"));
    assertTrue(error.getDetails().contains("LicenseRef-MIT-License"));
    assertTrue(error.getDetails().contains("LicenseRef-MIT-license"));
  }

  // Verifies complete-token rewriting in scalar expressions and package, file, and snippet arrays.
  @Test
  void testLocalLicenseReferencesAreRewrittenInExpressions() throws Exception {
    // Given local references in every SPDX 2.3 licensing field, including compound expressions
    var sbom = loadCaseOnlyLicenseRefs();
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
    var normalized = normalizeJson(sbom);

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

  // Verifies that longer IDs, external references, and literal text keep their original meaning.
  @Test
  void testNonLocalAndUnrelatedValuesAreNotRewritten() throws Exception {
    // Given a longer independent license ID, an external license, and literal occurrences
    var sbom = loadCaseOnlyLicenseRefs();
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
    var normalized = normalizeJson(sbom);

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

  // Verifies that locale-specific case folding cannot split an otherwise equivalent ID pair.
  @Test
  void testCaseOnlyLicenseReferencesAreLocaleIndependent() throws Exception {
    // Given a lowercase variant and a Turkish default locale
    var original = Locale.getDefault();
    var sbom = loadCaseOnlyLicenseRefs();
    ((ObjectNode) sbom.withArray("hasExtractedLicensingInfos").get(1))
        .put("licenseId", "LicenseRef-mit-license");
    ((ObjectNode) sbom.withArray("packages").get(2))
        .put("licenseDeclared", "LicenseRef-mit-license")
        .put("licenseConcluded", "LicenseRef-mit-license");
    try {
      Locale.setDefault(Locale.forLanguageTag("tr-TR"));
      // When parsing and normalizing under that locale
      var normalized = normalizeJson(sbom);
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
    var sbom = createNonCollidingLicenseRefs(variant);

    // When parsing the document
    var wrapper = new SpdxWrapper(createJsonStream(sbom));

    // Then package discovery is unchanged and unrelated definitions are not removed
    assertEquals(
        Set.of(new PackageRef("pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final")),
        wrapper.getStartFromPackages());
    assertEquals(
        variant.equals("distinct") ? 2 : variant.equals("single") ? 1 : 0,
        getParsedDocument(wrapper).getExtractedLicenseInfos().size());
  }

  // Verifies the common path preserves the original bytes without allocating a JSON object tree.
  @ParameterizedTest
  @ValueSource(strings = {"missing", "empty", "single", "distinct"})
  void testNonCollidingDocumentIsReturnedUnchangedWithoutJsonTree(String variant) throws Exception {
    // Given a non-colliding document with whitespace that serialization would change
    byte[] content =
        (" \n" + MAPPER.writeValueAsString(createNonCollidingLicenseRefs(variant)) + "\n ")
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

  // Verifies that definitions preceding a supported SPDX 2.x version still merge.
  @ParameterizedTest
  @ValueSource(
      strings = {
        Version.TWO_POINT_ZERO_VERSION,
        Version.TWO_POINT_ONE_VERSION,
        Version.TWO_POINT_TWO_VERSION,
        Version.TWO_POINT_THREE_VERSION
      })
  void testLicenseReferenceNormalizationWithVersionLast(String version) throws Exception {
    // Given colliding definitions before the root version field
    var sbom = loadCaseOnlyLicenseRefs();
    sbom.remove("spdxVersion");
    sbom.put("spdxVersion", version);
    var expected = sbom.deepCopy();
    expected.withArray("hasExtractedLicensingInfos").remove(1);
    ((ObjectNode) expected.withArray("packages").get(2))
        .put("licenseDeclared", "LicenseRef-MIT-License")
        .put("licenseConcluded", "LicenseRef-MIT-License");

    // When normalizing the reordered document
    try (var normalized = normalize(createJsonStream(sbom))) {
      // Then the definitions and local references use the first spelling
      assertEquals(expected, MAPPER.readTree(normalized));
    }
  }

  // Verifies that versions outside supported SPDX 2.x are returned unchanged.
  @ParameterizedTest
  @ValueSource(strings = {"SPDX-3.0", "SPDX-2.4"})
  void testOtherVersionsAreReturnedUnchanged(String version) throws Exception {
    // Given collisions followed by a version outside the normalizer's scope
    var sbom = loadCaseOnlyLicenseRefs();
    sbom.remove("spdxVersion");
    sbom.put("spdxVersion", version);
    byte[] content = MAPPER.writeValueAsBytes(sbom);

    // When normalizing the document
    try (var normalized = normalize(new ByteArrayInputStream(content))) {
      // Then neither the definitions nor their references nor formatting change
      assertArrayEquals(content, normalized.readAllBytes());
    }
  }

  // Verifies that the parser still rejects unsupported future SPDX versions.
  @ParameterizedTest
  @ValueSource(strings = {"SPDX-2.4"})
  void testUnsupportedVersionIsRejected(String version) throws Exception {
    // Given a document declaring a version the SPDX parser does not support
    var sbom = loadCaseOnlyLicenseRefs(version);

    // When parsing the document
    // Then the existing version-validation policy still rejects it
    assertThrows(SpdxValidationException.class, () -> new SpdxWrapper(createJsonStream(sbom)));
  }

  // Verifies malformed JSON still produces an SPDX validation exception.
  @Test
  void testMalformedJsonIsRejected() {
    assertThrows(
        SpdxValidationException.class,
        () -> new SpdxWrapper(new ByteArrayInputStream("{".getBytes(StandardCharsets.UTF_8))));
  }

  // Supplies every conflict variant for each supported SPDX 2.x version.
  private static Stream<Arguments> supplyConflictingDefinitionsAcrossVersions() {
    return Stream.of(
            Version.TWO_POINT_ZERO_VERSION,
            Version.TWO_POINT_ONE_VERSION,
            Version.TWO_POINT_TWO_VERSION,
            Version.TWO_POINT_THREE_VERSION)
        .flatMap(
            version ->
                Stream.of(
                        "extractedText",
                        "name",
                        "comment",
                        "seeAlsos",
                        "missingName",
                        "noAssertionName",
                        "emptySeeAlsos")
                    .map(difference -> Arguments.of(version, difference)));
  }

  private static ObjectNode loadCaseOnlyLicenseRefs() throws IOException {
    try (var input = stream(CASE_ONLY_LICENSE_REFS)) {
      return (ObjectNode) MAPPER.readTree(input);
    }
  }

  // Loads the reproducer with the requested SPDX 2.x document version.
  private static ObjectNode loadCaseOnlyLicenseRefs(String version) throws IOException {
    var sbom = loadCaseOnlyLicenseRefs();
    sbom.put("spdxVersion", version);
    return sbom;
  }

  private static ObjectNode createNonCollidingLicenseRefs(String variant) throws IOException {
    var sbom = loadCaseOnlyLicenseRefs();
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

  private static InputStream createJsonStream(ObjectNode sbom) throws IOException {
    return new ByteArrayInputStream(MAPPER.writeValueAsBytes(sbom));
  }

  private static SpdxDocument getParsedDocument(SpdxWrapper wrapper)
      throws ReflectiveOperationException {
    var field = SpdxWrapper.class.getDeclaredField("doc");
    field.setAccessible(true);
    return (SpdxDocument) field.get(wrapper);
  }

  // Asserts every package declaring the case-only reference points at the canonical definition.
  private static void assertPackagesUseLicense(SpdxDocument document, String licenseId)
      throws InvalidSPDXAnalysisException {
    for (var id : LICENSE_REF_PACKAGE_IDS) {
      var pkg =
          new SpdxPackage(document.getModelStore(), document.getDocumentUri(), id, null, false);
      assertEquals(licenseId, pkg.getLicenseDeclared().toString(), id);
      assertEquals(licenseId, pkg.getLicenseConcluded().toString(), id);
    }
  }

  // Inspect the compatibility boundary as well as parsing: the library can otherwise mask stale
  // reference spellings through its own case-insensitive lookups. Keep this access test-only.
  private static ObjectNode normalizeJson(ObjectNode sbom) throws Exception {
    new SpdxWrapper(createJsonStream(sbom));
    try (var input = normalize(createJsonStream(sbom))) {
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
