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

package io.github.guacsec.trustifyda.integration.licenses;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.LicenseInfoFactory;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.expandedlicensing.ConjunctiveLicenseSet;
import org.spdx.library.model.v3_0_1.expandedlicensing.DisjunctiveLicenseSet;
import org.spdx.library.model.v3_0_1.expandedlicensing.ListedLicense;
import org.spdx.library.model.v3_0_1.expandedlicensing.ListedLicenseException;
import org.spdx.library.model.v3_0_1.expandedlicensing.WithAdditionOperator;
import org.spdx.library.model.v3_0_1.simplelicensing.AnyLicenseInfo;
import org.spdx.storage.simple.InMemSpdxStore;
import org.spdx.utility.license.LicenseExpressionParser;

import io.github.guacsec.trustifyda.api.v5.LicenseCategory;
import io.github.guacsec.trustifyda.api.v5.LicenseInfo;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;

@QuarkusTest
public class SpdxLicenseServiceTest {

  @Inject private SpdxLicenseService service;

  @Test
  void testFromLicenseId_andExpression() {
    LicenseInfo info = service.fromLicenseId("MIT AND GPL-3.0", null, null);
    assertNotNull(info.getIdentifiers());
    assertEquals(2, info.getIdentifiers().size());
    info.getIdentifiers()
        .forEach(
            license ->
                assertTrue(license.getId().equals("MIT") || license.getId().equals("GPL-3.0")));
  }

  @Test
  void testFromLicenseId_orExpression() {
    LicenseInfo info = service.fromLicenseId("MIT OR GPL-3.0", null, null);
    assertNotNull(info.getIdentifiers());
    assertEquals(2, info.getIdentifiers().size());
    assertEquals(LicenseCategory.PERMISSIVE, info.getCategory());
    info.getIdentifiers()
        .forEach(
            license ->
                assertTrue(license.getId().equals("MIT") || license.getId().equals("GPL-3.0")));
  }

  @Test
  void testFromLicenseId_withException() {
    // Use deprecated SPDX id (GPL-2.0-with-classpath-exception) accepted by the library
    LicenseInfo info =
        service.fromLicenseId("MIT AND GPL-2.0-with-classpath-exception", null, null);
    assertNotNull(info.getIdentifiers());
    assertEquals(2, info.getIdentifiers().size());
    var mitLicense =
        info.getIdentifiers().stream()
            .filter(license -> license.getId().equals("MIT"))
            .findFirst()
            .orElseThrow(() -> new RuntimeException("MIT license not found"));
    assertEquals(LicenseCategory.PERMISSIVE, mitLicense.getCategory());
    var gplWithException =
        info.getIdentifiers().stream()
            .filter(
                license ->
                    license.getId().equals("GPL-2.0-with-classpath-exception")
                        || license.getId().equals("GPL-2.0-only WITH Classpath-exception-2.0")
                        || license.getId().equals("GPL-2.0-only")
                        || license.getId().equals("GPL-2.0"))
            .findFirst()
            .orElseThrow(
                () -> new RuntimeException("GPL-2.0-with-classpath-exception license not found"));
    assertEquals(LicenseCategory.WEAK_COPYLEFT, gplWithException.getCategory());
    // When id includes WITH, name should include exception (e.g. "with Classpath exception 2.0")
    if (gplWithException.getId().contains(" WITH ")) {
      assertTrue(
          gplWithException.getName().toLowerCase().contains("with"),
          "Name should include exception: " + gplWithException.getName());
    }
  }

  @BeforeAll
  static void initSpdxLibrary() {
    SpdxModelFactory.init();
  }

  @Test
  void testSpdxJavaLib() throws InvalidSPDXAnalysisException {
    var modelStore = new InMemSpdxStore();
    AnyLicenseInfo parsedDeprecated =
        LicenseExpressionParser.parseLicenseExpression(
            "GPL-2.0-with-classpath-exception", modelStore, null, null, null);
    AnyLicenseInfo parsedModern =
        LicenseExpressionParser.parseLicenseExpression(
            "GPL-2.0-only WITH Classpath-exception-2.0", modelStore, null, null, null);
    assertTrue(parsedDeprecated instanceof ListedLicense);
    assertTrue(parsedModern instanceof WithAdditionOperator);
    // ListedLicense id is full deprecated id when parsed as single token
    assertTrue(
        parsedDeprecated.toString().equals("GPL-2.0-with-classpath-exception")
            || parsedDeprecated.toString().contains("GPL-2.0"));
  }

  // ---- SPDX library parsing tests (equivalent to service behavior, no categories) ----

  /** Deprecated form: single token "GPL-2.0-with-classpath-exception" parses as ListedLicense. */
  @Test
  void testSpdxLib_deprecatedForm_parsesAsListedLicense() throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info =
        LicenseExpressionParser.parseLicenseExpression(
            "GPL-2.0-with-classpath-exception", new InMemSpdxStore(), null, null, null);
    assertTrue(info instanceof ListedLicense);
    ListedLicense lic = (ListedLicense) info;
    // ID is the full deprecated identifier
    String id = lic.toString();
    assertNotNull(id);
    assertTrue(id.contains("GPL-2.0") && id.contains("classpath"));
  }

  /**
   * Whether OSI/FSF/deprecated are populated when parsing with a custom InMemSpdxStore. If the
   * parser copies from the default listed-license store, they may be set; otherwise they are often
   * empty.
   */
  @Test
  void testSpdxLib_deprecatedForm_osiFsfDeprecated_withCustomStore()
      throws InvalidSPDXAnalysisException {
    var store = new InMemSpdxStore();
    AnyLicenseInfo info =
        LicenseExpressionParser.parseLicenseExpression(
            "GPL-2.0-with-classpath-exception", store, null, null, null);
    assertTrue(info instanceof ListedLicense);
    ListedLicense lic = (ListedLicense) info;
    var osi = lic.getIsOsiApproved();
    var fsf = lic.getIsFsfLibre();
    var deprecated = lic.getIsDeprecatedLicenseId();
    // Document: are they populated? (Optional.empty() or null means not populated)
    assertNotNull(osi);
    assertNotNull(fsf);
    assertNotNull(deprecated);
    // If you need OSI/FSF/deprecated for category logic, use
    // LicenseInfoFactory.getListedLicenseById(lic.toString()) when these are empty
  }

  /**
   * Using default store (parseSPDXLicenseString): OSI/FSF/deprecated should be populated from the
   * SPDX license list.
   */
  @Test
  void testSpdxLib_singleLicense_withDefaultStore_osiFsfDeprecated()
      throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info = LicenseInfoFactory.parseSPDXLicenseString("MIT");
    assertTrue(info instanceof ListedLicense);
    ListedLicense lic = (ListedLicense) info;
    var osi = lic.getIsOsiApproved();
    var fsf = lic.getIsFsfLibre();
    var deprecated = lic.getIsDeprecatedLicenseId();
    assertTrue(osi.isPresent() && Boolean.TRUE.equals(osi.get()));
    assertTrue(fsf.isPresent() && Boolean.TRUE.equals(fsf.get()));
    assertTrue(deprecated.isPresent() && Boolean.FALSE.equals(deprecated.get()));
  }

  /**
   * Deprecated listed license (e.g. GPL-2.0-with-classpath-exception) via default store: check if
   * deprecated flag and OSI/FSF are set.
   */
  @Test
  void testSpdxLib_deprecatedLicense_withDefaultStore_osiFsfDeprecated()
      throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info =
        LicenseInfoFactory.parseSPDXLicenseString("GPL-2.0-with-classpath-exception");
    assertTrue(info instanceof ListedLicense);
    ListedLicense lic = (ListedLicense) info;
    var osi = lic.getIsOsiApproved();
    var fsf = lic.getIsFsfLibre();
    var deprecated = lic.getIsDeprecatedLicenseId();
    // Document result: deprecated should be true; OSI/FSF may be set
    assertNotNull(deprecated);
    assertNotNull(osi);
    assertNotNull(fsf);
  }

  /** Modern form: "GPL-2.0-only WITH Classpath-exception-2.0" parses as WithAdditionOperator. */
  @Test
  void testSpdxLib_modernForm_parsesAsWithAdditionOperator() throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info =
        LicenseExpressionParser.parseLicenseExpression(
            "GPL-2.0-only WITH Classpath-exception-2.0", new InMemSpdxStore(), null, null, null);
    assertTrue(info instanceof WithAdditionOperator);
    WithAdditionOperator with = (WithAdditionOperator) info;
    assertNotNull(with.getSubjectExtendableLicense());
    assertNotNull(with.getSubjectAddition());
  }

  /**
   * Modern WITH form: we can detect there is an exception and get its id (for category conditions).
   * Exception name may be populated only when using default store; with custom InMemSpdxStore it is
   * often empty.
   */
  @Test
  void testSpdxLib_modernForm_exceptionHasIdAndName() throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info =
        LicenseExpressionParser.parseLicenseExpression(
            "GPL-2.0-only WITH Classpath-exception-2.0", new InMemSpdxStore(), null, null, null);
    assertTrue(info instanceof WithAdditionOperator);
    WithAdditionOperator with = (WithAdditionOperator) info;
    var addition = with.getSubjectAddition();
    assertNotNull(addition);
    assertTrue(addition instanceof ListedLicenseException);
    ListedLicenseException exception = (ListedLicenseException) addition;
    String exceptionId = exception.toString();
    assertNotNull(exceptionId);
    assertTrue(exceptionId.contains("Classpath") || exceptionId.contains("classpath"));
    // Name: with custom store often not populated; use getListedExceptionById(exceptionId) if
    // needed for category
    var nameOpt = exception.getName();
    assertNotNull(nameOpt);
  }

  /**
   * Modern WITH form with default store: exception id and name are populated for category logic.
   */
  @Test
  void testSpdxLib_modernForm_withDefaultStore_exceptionIdAndName()
      throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info =
        LicenseInfoFactory.parseSPDXLicenseString("GPL-2.0-only WITH Classpath-exception-2.0");
    assertTrue(info instanceof WithAdditionOperator);
    WithAdditionOperator with = (WithAdditionOperator) info;
    ListedLicenseException exception = (ListedLicenseException) with.getSubjectAddition();
    assertNotNull(exception);
    String exceptionId = exception.toString();
    assertNotNull(exceptionId);
    var nameOpt = exception.getName();
    assertTrue(nameOpt.isPresent(), "Exception name should be populated when using default store");
    assertNotNull(nameOpt.get());
  }

  /** AND expression: parsed as ConjunctiveLicenseSet with two members. */
  @Test
  void testSpdxLib_andExpression_conjunctiveSetWithTwoMembers()
      throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info =
        LicenseExpressionParser.parseLicenseExpression(
            "MIT AND GPL-3.0", new InMemSpdxStore(), null, null, null);
    assertTrue(info instanceof ConjunctiveLicenseSet);
    ConjunctiveLicenseSet andSet = (ConjunctiveLicenseSet) info;
    Set<AnyLicenseInfo> members = andSet.getMembers();
    assertNotNull(members);
    assertEquals(2, members.size());
    List<String> ids =
        members.stream()
            .map(m -> m instanceof ListedLicense ? ((ListedLicense) m).toString() : m.toString())
            .toList();
    assertTrue(ids.stream().anyMatch(id -> id.contains("MIT")));
    assertTrue(ids.stream().anyMatch(id -> id.contains("GPL-3.0")));
  }

  /** OR expression: parsed as DisjunctiveLicenseSet with two members. */
  @Test
  void testSpdxLib_orExpression_disjunctiveSetWithTwoMembers() throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info =
        LicenseExpressionParser.parseLicenseExpression(
            "MIT OR GPL-3.0", new InMemSpdxStore(), null, null, null);
    assertTrue(info instanceof DisjunctiveLicenseSet);
    DisjunctiveLicenseSet orSet = (DisjunctiveLicenseSet) info;
    Set<AnyLicenseInfo> members = orSet.getMembers();
    assertNotNull(members);
    assertEquals(2, members.size());
    List<String> ids =
        members.stream()
            .map(m -> m instanceof ListedLicense ? ((ListedLicense) m).toString() : m.toString())
            .toList();
    assertTrue(ids.stream().anyMatch(id -> id.contains("MIT")));
    assertTrue(ids.stream().anyMatch(id -> id.contains("GPL-3.0")));
  }

  /** Parenthesis: (MIT OR Apache-2.0) AND GPL-3.0 → AND of (OR of MIT, Apache-2.0) and GPL-3.0. */
  @Test
  void testSpdxLib_parenthesis_orAndStructure() throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info =
        LicenseExpressionParser.parseLicenseExpression(
            "(MIT OR Apache-2.0) AND GPL-3.0", new InMemSpdxStore(), null, null, null);
    assertTrue(info instanceof ConjunctiveLicenseSet);
    ConjunctiveLicenseSet andSet = (ConjunctiveLicenseSet) info;
    Set<AnyLicenseInfo> members = andSet.getMembers();
    assertEquals(2, members.size());
    // One member is DisjunctiveLicenseSet (MIT OR Apache-2.0), one is ListedLicense (GPL-3.0)
    long orSets = members.stream().filter(m -> m instanceof DisjunctiveLicenseSet).count();
    long listed = members.stream().filter(m -> m instanceof ListedLicense).count();
    assertEquals(1, orSets);
    assertEquals(1, listed);
    AnyLicenseInfo orMember =
        members.stream().filter(m -> m instanceof DisjunctiveLicenseSet).findFirst().orElseThrow();
    DisjunctiveLicenseSet orSet = (DisjunctiveLicenseSet) orMember;
    assertEquals(2, orSet.getMembers().size());
  }

  /** Single listed license: id and optional OSI/FSF/deprecated (with default store). */
  @Test
  void testSpdxLib_singleListedLicense_idAndMetadata() throws InvalidSPDXAnalysisException {
    AnyLicenseInfo info = LicenseInfoFactory.parseSPDXLicenseString("Apache-2.0");
    assertTrue(info instanceof ListedLicense);
    ListedLicense lic = (ListedLicense) info;
    String id = lic.toString();
    assertNotNull(id);
    assertTrue(id.contains("Apache-2.0"));
    assertTrue(lic.getIsOsiApproved().isPresent());
    assertTrue(lic.getIsFsfLibre().isPresent());
    assertTrue(lic.getIsDeprecatedLicenseId().isPresent());
  }

  @Test
  void testFromLicenseId_single() {
    LicenseInfo info = service.fromLicenseId("MIT", null, null);
    assertNotNull(info.getIdentifiers());
    assertEquals(1, info.getIdentifiers().size());
    assertEquals("MIT", info.getIdentifiers().get(0).getId());
    assertEquals(LicenseCategory.PERMISSIVE, info.getCategory());
  }

  @Test
  void testFromLicenseId_morePermissive() {
    LicenseInfo info = service.fromLicenseId("MIT OR GPL-3.0", null, null);
    assertEquals(LicenseCategory.PERMISSIVE, info.getCategory());
  }

  @Test
  void testFromLicenseId_moreRestrictive() {
    LicenseInfo info = service.fromLicenseId("GPL-3.0 AND MIT", null, null);
    assertEquals(LicenseCategory.STRONG_COPYLEFT, info.getCategory());
  }

  @Test
  void testFromLicenseId_unknown() {
    LicenseInfo info = service.fromLicenseId("UNKNOWN", null, null);
    assertEquals(LicenseCategory.UNKNOWN, info.getCategory());
    assertNotNull(info.getIdentifiers());
    assertEquals(1, info.getIdentifiers().size());
    assertEquals("UNKNOWN", info.getIdentifiers().get(0).getId());
  }

  @Test
  void testFromLicenseId_withExceptionSuffix() {
    LicenseInfo infoOnly = service.fromLicenseId("GPL-2.0-only", null, null);
    assertEquals(LicenseCategory.STRONG_COPYLEFT, infoOnly.getCategory());
    LicenseInfo infoWithException =
        service.fromLicenseId("GPL-2.0-with-classpath-exception", null, null);
    assertEquals(LicenseCategory.WEAK_COPYLEFT, infoWithException.getCategory());
  }

  /** Evidence name is human-readable; expression is normalized (e.g. WITH form). */
  @Test
  void testFromLicenseId_humanReadableNameAndNormalizedExpression() {
    LicenseInfo info = service.fromLicenseId("GPL-2.0-with-classpath-exception", null, null);
    assertNotNull(info.getName());
    assertTrue(
        info.getName().toLowerCase().contains("general")
            || info.getName().toLowerCase().contains("license"),
        "Name should be human-readable: " + info.getName());
    assertNotNull(info.getExpression());
    assertTrue(
        info.getExpression().contains(" WITH "),
        "Expression should be normalized (WITH form): " + info.getExpression());
  }

  /** Single deprecated id (e.g. from deps.dev) is normalized to canonical id/name/expression. */
  @Test
  void testFromLicenseId_deprecatedIdNormalizedToWithForm() {
    LicenseInfo info = service.fromLicenseId("GPL-2.0-with-classpath-exception", null, null);
    assertEquals("GPL-2.0-only WITH Classpath-exception-2.0", info.getExpression());
    assertNotNull(info.getIdentifiers());
    assertEquals(1, info.getIdentifiers().size());
    assertEquals("GPL-2.0-only WITH Classpath-exception-2.0", info.getIdentifiers().get(0).getId());
    assertTrue(
        info.getIdentifiers().get(0).getName().toLowerCase().contains("classpath"),
        "Name should include exception: " + info.getIdentifiers().get(0).getName());
  }

  @Test
  void testFromLicenseId_expressionRequired() {
    assertThrows(NotFoundException.class, () -> service.fromLicenseId(null, null, null));
    assertThrows(NotFoundException.class, () -> service.fromLicenseId("", null, null));
    assertThrows(NotFoundException.class, () -> service.fromLicenseId("   ", null, null));
  }

  @Test
  void testIdentifyLicense_apache20() throws InvalidSPDXAnalysisException {
    var licenseContent = getClass().getClassLoader().getResourceAsStream("licenses/Apache-2.0.txt");
    try {
      var license = service.identifyLicense(new String(licenseContent.readAllBytes()));
      assertEquals("Apache-2.0", license.getId());
    } catch (NotFoundException | IOException e) {
      fail("Error identifying license", e);
    }
  }

  @Test
  void testIdentifyLicense_mit() throws InvalidSPDXAnalysisException {
    var licenseContent = getClass().getClassLoader().getResourceAsStream("licenses/MIT.txt");
    try {
      var license = service.identifyLicense(new String(licenseContent.readAllBytes()));
      assertEquals("MIT", license.getId());
    } catch (NotFoundException | IOException e) {
      fail("Error identifying license", e);
    }
  }

  @Test
  void testIdentifyLicense_gpl20_with_classpath_exception() throws InvalidSPDXAnalysisException {
    var licenseContent =
        getClass()
            .getClassLoader()
            .getResourceAsStream("licenses/GPL-2.0-with-classpath-exception.txt");
    assertThrows(
        NotFoundException.class,
        () -> service.identifyLicense(new String(licenseContent.readAllBytes())));
  }

  @Test
  void testIdentifyLicense_unknown() {
    var licenseContent = """
        Unknown License
        """;
    assertThrows(NotFoundException.class, () -> service.identifyLicense(licenseContent));
  }
}
