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

package io.github.guacsec.trustifyda.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.api.v5.CvssVector;

public class CvssParserTest {

  private static final String[] INPUTS = {
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:L/E:U/RL:U/RC:R",
    "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:L/E:U/RL:U/RC:R",
  };

  private static final CvssVector[] EXPECTATIONS = {
    new CvssVector()
        .attackVector("Network")
        .attackComplexity("High")
        .privilegesRequired("None")
        .userInteraction("None")
        .scope("Unchanged")
        .confidentialityImpact("None")
        .integrityImpact("None")
        .availabilityImpact("High")
        .cvss(INPUTS[0]),
    new CvssVector()
        .attackVector("Adjacent Network")
        .attackComplexity("High")
        .privilegesRequired("Low")
        .userInteraction("Required")
        .scope("Unchanged")
        .confidentialityImpact("High")
        .integrityImpact("Low")
        .availabilityImpact("Low")
        .exploitCodeMaturity("Unproven that exploit exists")
        .remediationLevel("Unavailable")
        .reportConfidence("Reasonable")
        .cvss(INPUTS[1])
  };

  @Test
  void testVectorsV3() {
    for (int i = 0; i < INPUTS.length; i++) {
      var expectation = EXPECTATIONS[i % 2].cvss(INPUTS[i]);
      assertEquals(expectation, CvssParser.fromVectorString(INPUTS[i]), "Failed: " + INPUTS[i]);
    }
  }

  private static final String[] INPUTS_V2 = {
    "AV:N/AC:L/Au:N/C:N/I:N/A:P", "AV:A/AC:H/Au:S/C:P/I:P/A:C"
  };

  private static final CvssVector[] EXPECTATIONS_V2 = {
    new CvssVector()
        .attackVector("Network")
        .attackComplexity("Low")
        .privilegesRequired("None")
        .confidentialityImpact("None")
        .integrityImpact("None")
        .availabilityImpact("Low")
        .userInteraction(null)
        .scope(null)
        .cvss(INPUTS_V2[0]),
    new CvssVector()
        .attackVector("Adjacent Network")
        .attackComplexity("High")
        .privilegesRequired("Low")
        .confidentialityImpact("Low")
        .integrityImpact("Low")
        .availabilityImpact("High")
        .userInteraction(null)
        .scope(null)
        .exploitCodeMaturity(null)
        .remediationLevel(null)
        .reportConfidence(null)
        .cvss(INPUTS_V2[1])
  };

  @Test
  void testVectorsV2() {
    for (int i = 0; i < INPUTS_V2.length; i++) {
      assertEquals(
          EXPECTATIONS_V2[i], CvssParser.fromVectorString(INPUTS_V2[i]), "Failed: " + INPUTS_V2[i]);
    }
  }
}
