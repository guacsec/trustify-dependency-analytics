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

package io.github.guacsec.trustifyda.integration.trustedcontent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.camel.Exchange;
import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.trustedcontent.ubi.UBIRecommendation;
import io.github.guacsec.trustifyda.model.trustedcontent.IndexedRecommendation;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;

import jakarta.inject.Inject;

@QuarkusTest
@TestProfile(TcResponseHandlerTest.SbomIdTestProfile.class)
class TcResponseHandlerTest {

  private static final String EXPECTED_UBI_RECOMMENDATION = "pkg:oci/ubi@0.0.2";

  @Inject TcResponseHandler handler;

  @Inject UBIRecommendation mapping;

  @Test
  void testAggregation() throws IOException {
    var response =
        handler.processRecommendations(
            mock(Exchange.class),
            getClass()
                .getClassLoader()
                .getResourceAsStream("__files/trustedcontent/simple.json")
                .readAllBytes(),
            null);
    assertNotNull(response);
    assertTrue(response.status().getOk());
    assertEquals("OK", response.status().getMessage());
    assertEquals(200, response.status().getCode());
    assertEquals(Constants.TRUSTED_CONTENT_PROVIDER, response.status().getName());

    assertEquals(3, response.recommendations().size());

    Map<String, ExpectedRecommendation> expectations = new HashMap<>();
    expectations.put(
        "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5?type=jar",
        new ExpectedRecommendation(
            "1.2.5.redhat-00003", Set.of("CVE-2023-2974", "CVE-2023-1584", "CVE-2023-28867")));
    expectations.put(
        "pkg:maven/io.quarkus/quarkus-narayana-jta@2.13.5.Final?type=jar",
        new ExpectedRecommendation(
            "2.13.8.Final-redhat-00006",
            Set.of("CVE-2020-36518", "CVE-2023-44487", "CVE-2023-4853")));

    expectations.put(
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar",
        new ExpectedRecommendation("2.13.4.2-redhat-00001", Collections.emptySet()));

    expectations
        .entrySet()
        .forEach(
            e -> {
              var r = response.recommendations().get(new PackageRef(e.getKey()));
              assertNotNull(r);
              assertEquals(e.getValue().version(), r.packageName().version());
              assertEquals(e.getValue().cves().size(), r.vulnerabilities().size());
              assertTrue(e.getValue().cves().containsAll(r.vulnerabilities().keySet()));
            });
  }

  @Test
  void testEmpty() throws IOException {
    var response =
        handler.processRecommendations(
            mock(Exchange.class),
            getClass()
                .getClassLoader()
                .getResourceAsStream("__files/trustedcontent/empty_report.json")
                .readAllBytes(),
            null);
    assertNotNull(response);
    assertTrue(response.status().getOk());
    assertEquals("OK", response.status().getMessage());
    assertEquals(200, response.status().getCode());
    assertEquals(Constants.TRUSTED_CONTENT_PROVIDER, response.status().getName());

    assertTrue(response.recommendations().isEmpty());
  }

  @Test
  void testSbomId() throws IOException {
    String sbomId = "pkg:oci/alpine@0.0.1";
    handler.ubiRecommendation = mapping;
    var response =
        handler.processRecommendations(
            mock(Exchange.class),
            getClass()
                .getClassLoader()
                .getResourceAsStream("__files/trustedcontent/empty_report.json")
                .readAllBytes(),
            sbomId);
    assertNotNull(response);
    assertTrue(response.status().getOk());
    assertEquals("OK", response.status().getMessage());
    assertEquals(200, response.status().getCode());
    assertEquals(Constants.TRUSTED_CONTENT_PROVIDER, response.status().getName());

    PackageRef sbomRef = new PackageRef(sbomId);
    IndexedRecommendation recommendation =
        new IndexedRecommendation(new PackageRef(EXPECTED_UBI_RECOMMENDATION), null);
    assertEquals(1, response.recommendations().size());
    assertEquals(recommendation, response.recommendations().get(sbomRef));
  }

  private static final record ExpectedRecommendation(String version, Set<String> cves) {}

  public static class SbomIdTestProfile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "trustedcontent.recommendation.ubi.mapping.alpine", EXPECTED_UBI_RECOMMENDATION);
    }
  }
}
