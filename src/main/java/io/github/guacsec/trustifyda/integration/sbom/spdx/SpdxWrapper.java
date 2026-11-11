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

package io.github.guacsec.trustifyda.integration.sbom.spdx;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.TypedValue;
import org.spdx.jacksonstore.MultiFormatStore;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.Checksum;
import org.spdx.library.model.v2.ExternalRef;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxDocument;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.SpdxVerificationHelper;
import org.spdx.library.model.v2.enumerations.RelationshipType;
import org.spdx.storage.simple.InMemSpdxStore;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.config.ObjectMapperProducer;
import io.github.guacsec.trustifyda.config.exception.DetailedException;
import io.github.guacsec.trustifyda.config.exception.SpdxValidationException;

public class SpdxWrapper {

  private static final String PURL_REFERENCE = "http://spdx.org/rdf/references/purl";
  private static final ObjectMapper MAPPER = ObjectMapperProducer.newInstance();
  private static final Pattern LICENSE_REFERENCE = Pattern.compile("LicenseRef-[A-Za-z0-9.-]+");
  private static final Pattern LOCAL_LICENSE_REFERENCE =
      Pattern.compile("(?<![A-Za-z0-9.:-])LicenseRef-[A-Za-z0-9.-]+");
  private static final Set<String> LICENSE_EXPRESSION_FIELDS =
      Set.of(
          "licenseDeclared",
          "licenseConcluded",
          "licenseInfoFromFiles",
          "licenseInfoInFiles",
          "licenseInfoInSnippets");

  private MultiFormatStore inputStore;
  private SpdxDocument doc;
  private String docUri;
  private Map<PackageRef, Set<PackageRef>> relationships;
  private Set<PackageRef> startFrom = new HashSet<>();
  private Map<String, Map<String, String>> componentHashes = new HashMap<>();

  static {
    SpdxModelFactory.init();
  }

  public SpdxWrapper(InputStream input) throws SpdxValidationException {
    this.inputStore =
        new MultiFormatStore(new InMemSpdxStore(), MultiFormatStore.Format.JSON_PRETTY);
    try {
      this.inputStore.deSerialize(normalizeLicenseReferences(input), false);
      var uris = inputStore.getDocumentUris();
      if (uris == null || uris.isEmpty()) {
        throw new SpdxValidationException(
            "SPDX document has no document URIs; the input may not be a valid SPDX document.");
      }
      this.docUri = uris.iterator().next();
      this.doc = new SpdxDocument(inputStore, docUri, null, false);
      this.relationships = buildRelationships();

    } catch (InvalidSPDXAnalysisException | IOException e) {
      throw new SpdxValidationException("Unable to parse SPDX SBOM", e);
    }
  }

  /**
   * The SPDX store rejects some case-only URI collisions before building the graph. Merge only
   * equivalent SPDX 2.x definitions and redirect their local uses before entering that store.
   * Non-colliding documents retain their original bytes without allocating a second JSON tree.
   */
  private static InputStream normalizeLicenseReferences(InputStream input) throws IOException {
    byte[] content = input.readAllBytes();
    if (!hasLicenseReferenceCollisions(content)) {
      return new ByteArrayInputStream(content);
    }

    var document = (ObjectNode) MAPPER.readTree(content);
    var canonicalIds = mergeLicenseDefinitions(document);
    rewriteLicenseReferences(document, canonicalIds);
    return new ByteArrayInputStream(MAPPER.writeValueAsBytes(document));
  }

  private static boolean hasLicenseReferenceCollisions(byte[] content) throws IOException {
    try (var parser = MAPPER.createParser(content)) {
      if (parser.nextToken() != JsonToken.START_OBJECT) {
        return false;
      }
      boolean supportedVersion = false;
      boolean collisions = false;
      while (parser.nextToken() == JsonToken.FIELD_NAME) {
        String field = parser.currentName();
        JsonToken value = parser.nextToken();
        if ("spdxVersion".equals(field)) {
          supportedVersion =
              value == JsonToken.VALUE_STRING && isSupportedSpdx2Version(parser.getText());
        } else if ("hasExtractedLicensingInfos".equals(field)) {
          collisions = value == JsonToken.START_ARRAY && hasDuplicateLicenseIds(parser);
        }
        parser.skipChildren();
      }
      // The version may follow the definitions, so inspect all root fields before deciding.
      return supportedVersion && collisions;
    }
  }

  /**
   * Returns whether the version belongs to the set of SPDX 2.x versions the SPDX parser accepts.
   * Reusing the parser's own validation policy keeps compatibility handling aligned with what RHDA
   * can actually parse and excludes arbitrary future version strings such as SPDX-2.4.
   */
  private static boolean isSupportedSpdx2Version(String version) {
    return SpdxVerificationHelper.SUPPORTED_SPDX_VERSIONS.contains(version);
  }

  private static boolean hasDuplicateLicenseIds(JsonParser parser) throws IOException {
    Set<String> ids = new HashSet<>();
    boolean collisions = false;
    while (parser.nextToken() != JsonToken.END_ARRAY) {
      if (parser.currentToken() != JsonToken.START_OBJECT) {
        parser.skipChildren();
        continue;
      }
      String id = readLicenseId(parser);
      if (id != null
          && LICENSE_REFERENCE.matcher(id).matches()
          && !ids.add(id.toLowerCase(Locale.ROOT))) {
        collisions = true;
      }
    }
    return collisions;
  }

  private static String readLicenseId(JsonParser parser) throws IOException {
    String id = null;
    while (parser.nextToken() == JsonToken.FIELD_NAME) {
      String field = parser.currentName();
      JsonToken value = parser.nextToken();
      if ("licenseId".equals(field)) {
        id = value == JsonToken.VALUE_STRING ? parser.getText() : null;
      }
      parser.skipChildren();
    }
    return id;
  }

  private static Map<String, String> mergeLicenseDefinitions(ObjectNode document) {
    Map<String, ObjectNode> firstDefinitions = new HashMap<>();
    Map<String, String> canonicalIds = new HashMap<>();
    ArrayNode retained = MAPPER.createArrayNode();
    for (JsonNode definition : document.withArray("hasExtractedLicensingInfos")) {
      JsonNode id = definition.path("licenseId");
      if (!(definition instanceof ObjectNode object)
          || !id.isTextual()
          || !LICENSE_REFERENCE.matcher(id.asText()).matches()) {
        retained.add(definition);
        continue;
      }
      String key = id.asText().toLowerCase(Locale.ROOT);
      ObjectNode first = firstDefinitions.putIfAbsent(key, object);
      if (first == null) {
        retained.add(definition);
      } else {
        if (!areLicenseDefinitionsEquivalent(first, object)) {
          throw new SpdxValidationException(
              "Conflicting SPDX LicenseRef definitions: "
                  + first.path("licenseId").asText()
                  + " and "
                  + id.asText());
        }
        canonicalIds.put(key, first.path("licenseId").asText());
      }
    }

    document.set("hasExtractedLicensingInfos", retained);
    return canonicalIds;
  }

  /**
   * Compares two case-colliding definitions by their normalized metadata, so that optional fields
   * using equivalent SPDX representations are not reported as a material conflict.
   */
  private static boolean areLicenseDefinitionsEquivalent(JsonNode first, JsonNode other) {
    return normalizeLicenseMetadata(first).equals(normalizeLicenseMetadata(other));
  }

  /**
   * Copies a LicenseRef definition into the canonical form used for equivalence checks. The license
   * ID is excluded because it is the case-variant being merged away. Optional fields are reduced to
   * the representation SPDX 2.3 assigns them: an absent name means NOASSERTION (section 10.3.1), an
   * empty cross-reference list contains no references, and neither name casing nor cross-reference
   * order changes a definition's meaning.
   */
  private static ObjectNode normalizeLicenseMetadata(JsonNode definition) {
    ObjectNode metadata = ((ObjectNode) definition).deepCopy();
    metadata.remove("licenseId");
    normalizeLicenseName(metadata);
    normalizeSeeAlsos(metadata);
    return metadata;
  }

  /**
   * Treats a NOASSERTION license name as an absent one and folds casing, so that equivalent names
   * compare equal.
   */
  private static void normalizeLicenseName(ObjectNode metadata) {
    JsonNode name = metadata.path("name");
    if (!name.isTextual()) {
      return;
    }
    String value = name.asText();
    if (SpdxConstantsCompatV2.NOASSERTION_VALUE.equalsIgnoreCase(value)) {
      metadata.remove("name");
    } else {
      metadata.put("name", value.toLowerCase(Locale.ROOT));
    }
  }

  /**
   * Drops an empty cross-reference list and orders the remaining unique entries, so that list
   * absence, emptiness, order, and duplicates do not affect the comparison.
   */
  private static void normalizeSeeAlsos(ObjectNode metadata) {
    JsonNode seeAlsos = metadata.remove("seeAlsos");
    if (!(seeAlsos instanceof ArrayNode array)) {
      // Keep unexpected non-array values so they still participate in the comparison.
      if (seeAlsos != null) {
        metadata.set("seeAlsos", seeAlsos);
      }
      return;
    }
    Set<JsonNode> distinct = new HashSet<>();
    array.forEach(distinct::add);
    if (distinct.isEmpty()) {
      return;
    }
    List<JsonNode> sorted = new ArrayList<>(distinct);
    sorted.sort(Comparator.comparing(JsonNode::toString));
    ArrayNode normalized = MAPPER.createArrayNode();
    sorted.forEach(normalized::add);
    metadata.set("seeAlsos", normalized);
  }

  private static void rewriteLicenseReferences(JsonNode node, Map<String, String> canonicalIds) {
    if (node instanceof ObjectNode object) {
      var fields = object.properties().iterator();
      while (fields.hasNext()) {
        var field = fields.next();
        JsonNode value = field.getValue();
        if (LICENSE_EXPRESSION_FIELDS.contains(field.getKey())) {
          if (value.isTextual()) {
            object.put(field.getKey(), rewriteLicenseExpression(value.asText(), canonicalIds));
          } else if (value instanceof ArrayNode expressions) {
            for (int i = 0; i < expressions.size(); i++) {
              if (expressions.get(i).isTextual()) {
                expressions.set(
                    i,
                    TextNode.valueOf(
                        rewriteLicenseExpression(expressions.get(i).asText(), canonicalIds)));
              }
            }
          }
        } else {
          rewriteLicenseReferences(value, canonicalIds);
        }
      }
    } else if (node.isArray()) {
      node.forEach(child -> rewriteLicenseReferences(child, canonicalIds));
    }
  }

  private static String rewriteLicenseExpression(
      String expression, Map<String, String> canonicalIds) {
    return LOCAL_LICENSE_REFERENCE
        .matcher(expression)
        .replaceAll(
            match ->
                Matcher.quoteReplacement(
                    canonicalIds.getOrDefault(
                        match.group().toLowerCase(Locale.ROOT), match.group())));
  }

  private PackageRef toPackageRef(SpdxPackage spdxPackage) {
    try {
      Optional<ExternalRef> ref =
          spdxPackage.getExternalRefs().stream()
              .filter(
                  r -> {
                    try {
                      return PURL_REFERENCE.equals(r.getReferenceType().getIndividualURI());
                    } catch (InvalidSPDXAnalysisException e) {
                      throw new SpdxValidationException("Unable to retrieve referenceType", e);
                    }
                  })
              .findFirst();
      if (ref.isEmpty()) {
        throw new SpdxValidationException(
            "Missing Purl External Reference for Package: "
                + "Package name: "
                + spdxPackage.getName().orElse("unknown"));
      }
      String locator = ref.get().getReferenceLocator();
      if (locator == null || locator.isBlank()) {
        throw new SpdxValidationException(
            "Package has missing or empty PURL locator: "
                + spdxPackage.getName().orElse("unknown"));
      }
      return new PackageRef(locator);
    } catch (InvalidSPDXAnalysisException e) {
      throw new SpdxValidationException("Unable to find PackageUrl from SpdxPackage", e);
    }
  }

  private void setStartFromPackages(
      SpdxPackage rootPackage, Set<String> validationErrors, Map<String, PackageRef> uriToRef)
      throws InvalidSPDXAnalysisException {
    for (var r : rootPackage.getRelationships()) {
      try {
        var related = r.getRelatedSpdxElement();
        if (related.isEmpty()) {
          continue;
        }
        var direction = RelationshipDirection.fromRelationshipType(r.getRelationshipType());
        if (RelationshipDirection.FORWARD.equals(direction)) {
          var pkg = buildSpdxPackage(related.get().toTypedValue());
          startFrom.add(toPackageRefCached(pkg, uriToRef));
        }
      } catch (SpdxValidationException | InvalidSPDXAnalysisException e) {
        if (!isPackageSkippedNoPurl(e)) {
          validationErrors.add(validationErrorDetail(e));
        }
      }
    }
  }

  /**
   * Packages without a PURL (or with an empty one) cannot be analyzed for vulnerabilities; we skip
   * them instead of treating them as validation errors.
   */
  private static boolean isPackageSkippedNoPurl(Exception e) {
    String detail = validationErrorDetail(e);
    return detail != null
        && (detail.contains("Missing Purl")
            || detail.contains("empty PURL locator")
            || detail.contains("missing or empty PURL locator"));
  }

  private static String validationErrorDetail(Exception e) {
    if (e instanceof DetailedException de
        && de.getDetails() != null
        && !de.getDetails().isBlank()) {
      return de.getDetails();
    }
    return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
  }

  private String findRootUri() throws InvalidSPDXAnalysisException {
    if (doc.getDocumentDescribes() != null && doc.getDocumentDescribes().size() == 1) {
      return doc.getDocumentDescribes().iterator().next().getObjectUri();
    }
    for (var r : doc.getRelationships()) {
      if (RelationshipType.DESCRIBES.equals(r.getRelationshipType())) {
        var related = r.getRelatedSpdxElement();
        if (related.isPresent()) {
          return related.get().getObjectUri();
        }
      }
      if (RelationshipType.DESCRIBED_BY.equals(r.getRelationshipType())) {
        return r.getObjectUri();
      }
    }
    throw new SpdxValidationException(
        "Missing root. Verify the SPDXRef-DOCUMENT DESCRIBES relationship matches the SPDXID"
            + " package");
  }

  private Map<PackageRef, Set<PackageRef>> buildRelationships()
      throws InvalidSPDXAnalysisException, SpdxValidationException {
    Map<PackageRef, Set<PackageRef>> result = new HashMap<>();
    Map<String, PackageRef> uriToRef = new HashMap<>();
    Set<String> validationErrors = new LinkedHashSet<>();
    String rootUri = findRootUri();
    inputStore
        .getAllItems(docUri, SpdxConstantsCompatV2.CLASS_SPDX_PACKAGE)
        .forEach(
            p -> {
              try {
                var pkg = buildSpdxPackage(p);
                if (isRoot(rootUri, pkg)) {
                  setStartFromPackages(pkg, validationErrors, uriToRef);
                }
                var pkgRef = toPackageRefCached(pkg, uriToRef);
                extractChecksum(pkg, pkgRef);
                for (var relationship : pkg.getRelationships()) {
                  var rType = relationship.getRelationshipType();
                  var related = relationship.getRelatedSpdxElement();
                  if (related.isEmpty()) {
                    continue;
                  }
                  var relatedPkg = buildSpdxPackage(related.get().toTypedValue());
                  var relatedRef = toPackageRefCached(relatedPkg, uriToRef);
                  if (isRoot(rootUri, relatedPkg)) {
                    startFrom.add(pkgRef);
                  }
                  switch (RelationshipDirection.fromRelationshipType(rType)) {
                    case FORWARD ->
                        result.computeIfAbsent(pkgRef, k -> new HashSet<>()).add(relatedRef);
                    case BACKWARDS ->
                        result.computeIfAbsent(relatedRef, k -> new HashSet<>()).add(pkgRef);
                    default -> {}
                  }
                }
              } catch (InvalidSPDXAnalysisException | SpdxValidationException e) {
                if (!isPackageSkippedNoPurl(e)) {
                  validationErrors.add(validationErrorDetail(e));
                }
              }
            });

    if (!validationErrors.isEmpty()) {
      try {
        String version = doc.getSpecVersion();
        throw new SpdxValidationException(version, new ArrayList<>(validationErrors));
      } catch (InvalidSPDXAnalysisException e) {
        throw new SpdxValidationException("SPDX", new ArrayList<>(validationErrors));
      }
    }
    return result;
  }

  private PackageRef toPackageRefCached(SpdxPackage pkg, Map<String, PackageRef> cache)
      throws InvalidSPDXAnalysisException, SpdxValidationException {
    String uri = pkg.getObjectUri();
    if (uri != null) {
      PackageRef cached = cache.get(uri);
      if (cached != null) {
        return cached;
      }
    }
    PackageRef ref = toPackageRef(pkg);
    if (uri != null) {
      cache.put(uri, ref);
    }
    return ref;
  }

  public Set<PackageRef> getStartFromPackages() {
    return this.startFrom;
  }

  public Map<PackageRef, Set<PackageRef>> getRelationships() {
    return this.relationships;
  }

  public Map<String, Map<String, String>> getComponentHashes() {
    return this.componentHashes;
  }

  private void extractChecksum(SpdxPackage pkg, PackageRef pkgRef)
      throws InvalidSPDXAnalysisException {
    Map<String, String> hashes = new HashMap<>();
    for (Checksum checksum : pkg.getChecksums()) {
      hashes.put(checksum.getAlgorithm().toString(), checksum.getValue());
    }
    if (!hashes.isEmpty()) {
      componentHashes.put(pkgRef.ref(), Collections.unmodifiableMap(hashes));
    }
  }

  private boolean isRoot(String rootUri, SpdxPackage spdxPackage)
      throws InvalidSPDXAnalysisException {
    if (spdxPackage == null || spdxPackage.getObjectUri() == null) {
      return false;
    }
    return rootUri.equals(spdxPackage.getObjectUri());
  }

  private SpdxPackage buildSpdxPackage(TypedValue element) throws InvalidSPDXAnalysisException {
    if (element == null) {
      throw new InvalidSPDXAnalysisException("Relationship element is null");
    }
    String objectUri = element.getObjectUri();
    if (objectUri == null
        || !objectUri.startsWith(docUri)
        || objectUri.length() <= docUri.length() + 1) {
      throw new InvalidSPDXAnalysisException(
          "Related element URI is null or not in this document: " + objectUri);
    }
    String localId = objectUri.substring(docUri.length() + 1);
    return new SpdxPackage(inputStore, docUri, localId, null, false);
  }

  private enum RelationshipDirection {
    FORWARD, // DEPENDS_ON, CONTAINED_BY, etc.
    BACKWARDS, // DEPENDENCY_OF, CONTAINS, etc.
    IGNORED; // Other relationship types

    static RelationshipDirection fromRelationshipType(RelationshipType type) {
      return switch (type) {
        case DESCRIBES,
            DEPENDS_ON,
            CONTAINED_BY,
            BUILD_DEPENDENCY_OF,
            OPTIONAL_COMPONENT_OF,
            OPTIONAL_DEPENDENCY_OF,
            PROVIDED_DEPENDENCY_OF,
            TEST_DEPENDENCY_OF,
            RUNTIME_DEPENDENCY_OF,
            DEV_DEPENDENCY_OF,
            ANCESTOR_OF ->
            FORWARD;
        case DESCRIBED_BY, DEPENDENCY_OF, DESCENDANT_OF, PACKAGE_OF, CONTAINS -> BACKWARDS;
        default -> IGNORED;
      };
    }
  }
}
