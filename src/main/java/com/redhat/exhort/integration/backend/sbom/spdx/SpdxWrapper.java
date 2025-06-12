/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.backend.sbom.spdx;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.jboss.logging.Logger;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.TypedValue;
import org.spdx.jacksonstore.MultiFormatStore;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.ExternalRef;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxDocument;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.enumerations.RelationshipType;
import org.spdx.storage.simple.InMemSpdxStore;

import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.config.exception.SpdxValidationException;

public class SpdxWrapper {

  private static final Logger LOGGER = Logger.getLogger(SpdxWrapper.class);
  private static final String PURL_REFERENCE = "http://spdx.org/rdf/references/purl";

  private MultiFormatStore inputStore;
  private SpdxDocument doc;
  private String docUri;
  private Map<PackageRef, Set<PackageRef>> relationships;
  private Set<PackageRef> startFrom = new HashSet<>();

  static {
    SpdxModelFactory.init();
  }

  public SpdxWrapper(InputStream input) throws SpdxValidationException {
    this.inputStore =
        new MultiFormatStore(new InMemSpdxStore(), MultiFormatStore.Format.JSON_PRETTY);
    try {
      this.inputStore.deSerialize(input, false);
      var uris = inputStore.getDocumentUris();
      if (uris != null && !uris.isEmpty()) {
        this.docUri = uris.iterator().next();
      }
      this.doc = new SpdxDocument(inputStore, docUri, null, false);

      var version = doc.getSpecVersion();
      var verify = doc.verify(version);
      if (!verify.isEmpty()) {
        throw new SpdxValidationException(version, verify);
      }
      this.relationships = buildRelationships();

    } catch (InvalidSPDXAnalysisException | IOException e) {
      throw new SpdxValidationException("Unable to parse SPDX SBOM", e);
    }
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
      return new PackageRef(ref.get().getReferenceLocator());
    } catch (InvalidSPDXAnalysisException e) {
      throw new SpdxValidationException("Unable to find PackageUrl from SpdxPackage", e);
    }
  }

  private void setStartFromPackages(SpdxPackage rootPackage) throws InvalidSPDXAnalysisException {
    for (var r : rootPackage.getRelationships()) {
      try {
        var direction = RelationshipDirection.fromRelationshipType(r.getRelationshipType());
        if (RelationshipDirection.FORWARD.equals(direction)) {
          var pkg = buildSpdxPackage(r.getRelatedSpdxElement().get().toTypedValue());
          startFrom.add(toPackageRef(pkg));
        }
      } catch (SpdxValidationException e) {
        // Ignore invalid packages
      }
    }
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
      throws InvalidSPDXAnalysisException {
    Map<PackageRef, Set<PackageRef>> result = new HashMap<>();
    String rootUri = findRootUri();
    inputStore
        .getAllItems(docUri, SpdxConstantsCompatV2.CLASS_SPDX_PACKAGE)
        .forEach(
            p -> {
              try {
                var pkg = buildSpdxPackage(p);
                if (isRoot(rootUri, pkg)) {
                  setStartFromPackages(pkg);
                }
                var pkgRef = toPackageRef(pkg);
                for (var relationship : pkg.getRelationships()) {
                  var rType = relationship.getRelationshipType();
                  var related = relationship.getRelatedSpdxElement();
                  if (related.isEmpty()) {
                    return;
                  }
                  var relatedPkg = buildSpdxPackage(related.get().toTypedValue());
                  var relatedRef = toPackageRef(relatedPkg);
                  if (isRoot(rootUri, relatedPkg)) {
                    startFrom.add(pkgRef);
                  }
                  switch (RelationshipDirection.fromRelationshipType(rType)) {
                    case FORWARD -> result
                        .computeIfAbsent(pkgRef, k -> new HashSet<>())
                        .add(relatedRef);
                    case BACKWARDS -> result
                        .computeIfAbsent(relatedRef, k -> new HashSet<>())
                        .add(pkgRef);
                    default -> {}
                  }
                }
              } catch (InvalidSPDXAnalysisException | SpdxValidationException e) {
                // Ignore
                LOGGER.debug("Ignored invalid SPDX package", e);
              }
            });

    return result;
  }

  public Set<PackageRef> getStartFromPackages() {
    return this.startFrom;
  }

  public Map<PackageRef, Set<PackageRef>> getRelationships() {
    return this.relationships;
  }

  private boolean isRoot(String rootUri, SpdxPackage spdxPackage)
      throws InvalidSPDXAnalysisException {
    if (spdxPackage == null || spdxPackage.getObjectUri() == null) {
      return false;
    }
    return rootUri.equals(spdxPackage.getObjectUri());
  }

  private SpdxPackage buildSpdxPackage(TypedValue element) throws InvalidSPDXAnalysisException {
    return new SpdxPackage(
        inputStore, docUri, element.getObjectUri().substring(docUri.length() + 1), null, false);
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
            ANCESTOR_OF -> FORWARD;
        case DESCRIBED_BY, DEPENDENCY_OF, DESCENDANT_OF, PACKAGE_OF, CONTAINS -> BACKWARDS;
        default -> IGNORED;
      };
    }
  }
}
