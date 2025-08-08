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

package com.redhat.exhort.integration.providers.osv;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;

import org.junit.jupiter.api.Test;

import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.DirectDependency;

import io.quarkus.test.junit.QuarkusTest;

import jakarta.inject.Inject;

@QuarkusTest
public class OsvResponseHandlerTest {

  @Inject OsvResponseHandler handler;

  @Test
  void testVectors() throws IOException, URISyntaxException {
    var providerResponse = getProviderResponse("onguard/maven_report.json");
    var postgresRef =
        PackageRef.builder().purl("pkg:maven/org.postgresql/postgresql@42.5.0?type=jar").build();
    var jacksonRef =
        PackageRef.builder()
            .purl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar")
            .build();
    var deps = new HashMap<PackageRef, DirectDependency>();
    deps.put(postgresRef, new DirectDependency(postgresRef, null));
    deps.put(jacksonRef, new DirectDependency(jacksonRef, null));
    var dependencyTree = new DependencyTree(deps);

    var report = handler.responseToIssues(providerResponse, null, dependencyTree);

    assertFalse(report.issues().isEmpty());
    assertEquals(2, report.issues().size());
    var jacksonIssues = report.issues().get(jacksonRef.ref());
    assertEquals(3, jacksonIssues.size());

    // Test V3.1 vector.
    var issue =
        jacksonIssues.stream().filter(i -> i.getCves().contains("CVE-2022-42004")).findFirst();
    assertTrue(issue.isPresent());
    assertEquals(7.5f, issue.get().getCvssScore());
    assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", issue.get().getCvss().getCvss());

    // Test V3.0 vector.
    issue = jacksonIssues.stream().filter(i -> i.getCves().contains("CVE-2022-42003")).findFirst();
    assertTrue(issue.isPresent());
    assertEquals(7.5f, issue.get().getCvssScore());
    assertEquals("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", issue.get().getCvss().getCvss());

    // Test V2.0 vector.
    issue = jacksonIssues.stream().filter(i -> i.getCves().contains("CVE-2020-36518")).findFirst();
    assertTrue(issue.isPresent());
    assertEquals(5.0f, issue.get().getCvssScore());
    assertEquals("AV:N/AC:L/Au:N/C:N/I:N/A:P", issue.get().getCvss().getCvss());
  }

  private byte[] getProviderResponse(String fileName) throws IOException, URISyntaxException {
    return Files.readAllBytes(
        Path.of(this.getClass().getClassLoader().getResource("__files/" + fileName).toURI()));
  }
}
