/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.model.v2.Version;

import com.redhat.exhort.config.exception.SpdxValidationException;
import com.redhat.exhort.integration.sbom.spdx.SpdxWrapper;

public class SpdxWrapperTest {

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
}
