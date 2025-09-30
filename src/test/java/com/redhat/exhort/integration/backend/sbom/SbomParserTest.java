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

package com.redhat.exhort.integration.backend.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.redhat.exhort.config.exception.ClientDetailedException;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.sbom.SbomParserFactory;
import com.redhat.exhort.integration.sbom.cyclonedx.CycloneDxParser;
import com.redhat.exhort.integration.sbom.spdx.SpdxParser;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class SbomParserTest {

  static final String MAVEN_PURL_TYPE = "maven";
  static final String NPM_PURL_TYPE = "npm";
  static final String PYPI_PURL_TYPE = "pypi";
  static final String GOLANG_PURL_TYPE = "golang";

  private static final Collection<String> MEDIA_TYPES =
      List.of(Constants.SPDX_MEDIATYPE_JSON, Constants.CYCLONEDX_MEDIATYPE_JSON);

  @Test
  void testInvalidContentType() {
    var ex =
        assertThrows(
            ClientErrorException.class, () -> SbomParserFactory.newInstance(MediaType.TEXT_PLAIN));
    assertEquals("Unsupported Content-Type header: " + MediaType.TEXT_PLAIN, ex.getMessage());
    assertEquals(
        Response.Status.UNSUPPORTED_MEDIA_TYPE.getStatusCode(), ex.getResponse().getStatus());
  }

  @Test
  void testCycloneDxContentType() {
    var parser = SbomParserFactory.newInstance(Constants.CYCLONEDX_MEDIATYPE_JSON);
    assertNotNull(parser);
    assertTrue(parser instanceof CycloneDxParser);
  }

  @Test
  void testSpdxContentType() {
    var parser = SbomParserFactory.newInstance(Constants.SPDX_MEDIATYPE_JSON);
    assertNotNull(parser);
    assertTrue(parser instanceof SpdxParser);
  }

  @ParameterizedTest
  @MethodSource("getMediaTypes")
  void testParseEmptySBOM(String mediaType) {
    var parser = SbomParserFactory.newInstance(mediaType);
    var fileName = String.format("%s/empty-sbom.json", getFolder(mediaType));
    var file = getClass().getClassLoader().getResourceAsStream(fileName);

    var tree = parser.buildTree(file);
    assertEquals(0, tree.dependencies().size());
  }

  @ParameterizedTest
  @MethodSource("getMediaTypes")
  void testSBOMWithoutDependencies(String mediaType) {
    var parser = SbomParserFactory.newInstance(mediaType);
    var fileName = String.format("%s/no-deps-sbom.json", getFolder(mediaType));
    var file = getClass().getClassLoader().getResourceAsStream(fileName);

    var tree = parser.buildTree(file);
    assertEquals(0, tree.dependencies().size());
  }

  @ParameterizedTest
  @MethodSource("getMediaTypes")
  void testParseInvalidSBOM(String mediaType) {
    var parser = SbomParserFactory.newInstance(mediaType);
    var file = getClass().getClassLoader().getResourceAsStream("invalid_deps_file.txt");
    var ex = assertThrows(ClientDetailedException.class, () -> parser.buildTree(file));
    assertNotNull(ex);
    assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), Integer.valueOf(ex.getStatus()));
  }

  @ParameterizedTest
  @MethodSource("getMediaTypes")
  void testMinimalSbom(String mediaType) {
    var parser = SbomParserFactory.newInstance(mediaType);
    var fileName = String.format("%s/minimal-sbom.json", getFolder(mediaType));
    var file = getClass().getClassLoader().getResourceAsStream(fileName);

    var tree = parser.buildTree(file);
    assertEquals(2, tree.dependencies().size());
    assertEquals(7, tree.transitiveCount());
  }

  @ParameterizedTest
  @MethodSource("getSbomUseCases")
  void testSbom(String mediaType, String pkgManager, int direct, int transitive) {
    var parser = SbomParserFactory.newInstance(mediaType);
    var fileName = String.format("%s/%s-sbom.json", getFolder(mediaType), pkgManager);
    var file = getClass().getClassLoader().getResourceAsStream(fileName);

    var tree = parser.buildTree(file);
    assertEquals(direct, tree.dependencies().size());
    assertEquals(transitive, tree.transitiveCount());
  }

  @Test
  void testSpdxReverseRelationships() {
    var mediaType = Constants.SPDX_MEDIATYPE_JSON;
    var parser = SbomParserFactory.newInstance(mediaType);
    var fileName = "spdx/reverse-sbom.json";
    var file = getClass().getClassLoader().getResourceAsStream(fileName);

    var tree = parser.buildTree(file);
    assertEquals(260, tree.dependencies().size());
    assertEquals(4, tree.transitiveCount());
  }

  @ParameterizedTest
  @MethodSource("getMediaTypes")
  void testSharedDependencies(String mediaType) {
    var parser = SbomParserFactory.newInstance(mediaType);
    var fileName = String.format("%s/shared-deps-sbom.json", getFolder(mediaType));
    var file = getClass().getClassLoader().getResourceAsStream(fileName);

    var tree = parser.buildTree(file);

    assertEquals(3, tree.dependencies().size());
    assertEquals(5, tree.transitiveCount());
  }

  @Test
  void testCyclicReferences() {
    var parser = SbomParserFactory.newInstance(Constants.SPDX_MEDIATYPE_JSON);
    var file = getClass().getClassLoader().getResourceAsStream("spdx/cyclic-sbom.json");
    var tree = parser.buildTree(file);
    assertEquals(2, tree.dependencies().size());
    assertEquals(9, tree.transitiveCount());
  }

  @Test
  void testComplexGolangCycloneDX() {
    var mediaType = Constants.CYCLONEDX_MEDIATYPE_JSON;
    var parser = SbomParserFactory.newInstance(mediaType);
    var fileName = String.format("%s/golang-complex.json", getFolder(mediaType));
    var file = getClass().getClassLoader().getResourceAsStream(fileName);

    var tree = parser.buildTree(file);

    assertEquals(40, tree.dependencies().size());
    assertEquals(900, tree.transitiveCount());
  }

  static Stream<String> getMediaTypes() {
    return MEDIA_TYPES.stream();
  }

  static Stream<Arguments> getSbomUseCases() {
    return getMediaTypes()
        .mapMulti(
            (t, consumer) -> {
              consumer.accept(arguments(t, MAVEN_PURL_TYPE, 2, 7));
              consumer.accept(arguments(t, GOLANG_PURL_TYPE, 2, 3));
              consumer.accept(arguments(t, NPM_PURL_TYPE, 2, 3));
              consumer.accept(arguments(t, PYPI_PURL_TYPE, 2, 1));
            });
  }

  private String getFolder(String mediaType) {
    return switch (mediaType) {
      case Constants.CYCLONEDX_MEDIATYPE_JSON -> "cyclonedx";
      case Constants.SPDX_MEDIATYPE_JSON -> "spdx";
      default -> fail("Not implemented: " + mediaType);
    };
  }
}
