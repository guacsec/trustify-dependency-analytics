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

package io.github.guacsec.trustifyda.modelcards;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.model.modelcards.api.ModelCardQueryItem;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.inject.Inject;

@QuarkusTest
public class ModelCardServiceTest {

  @Inject ModelCardService service;

  @Test
  public void testFind() {
    var queryItem = new ModelCardQueryItem();
    queryItem.setModelName("microsoft/phi-2");
    var reports = service.find(List.of(queryItem));
    assertEquals(1, reports.size());

    var report = reports.get(0);
    assertEquals("microsoft/phi-2", report.getModelName());
    assertEquals("Phi-2 Evaluation Report", report.getName());

    var metrics = report.getMetrics();
    assertNotNull(metrics);
    assertEquals(14, metrics.size());
  }

  @Test
  public void testFind_NotFound() {
    var queryItem = new ModelCardQueryItem();
    queryItem.setModelName("not-found");
    var reports = service.find(List.of(queryItem));
    assertEquals(0, reports.size());
  }

  @Test
  public void testFind_Empty() {
    var reports = service.find(List.of());
    assertEquals(0, reports.size());
  }

  @Test
  public void testFind_Null() {
    var reports = service.find(null);
    assertEquals(0, reports.size());
  }

  @Test
  public void testGet() {
    var report = service.get(UUID.fromString("550e8400-e29b-41d4-a716-446655440004"));
    assertNotNull(report);
    assertNotNull(report.getConfig());
    assertNotNull(report.getConfig().getModelName());
    assertEquals("Phi-2 Evaluation Report", report.getName());
    assertEquals("microsoft/phi-2", report.getConfig().getModelName());
    assertEquals("microsoft", report.getSource());

    var tasks = report.getTasks();
    assertNotNull(tasks);
    assertEquals(5, tasks.size());
    var bbqTask = tasks.stream().filter(t -> t.getName().equals("bbq")).findFirst().orElseThrow();
    var bbqMetrics = bbqTask.getMetrics();
    assertEquals(9, bbqMetrics.size());
    var biasScoreMetric =
        bbqMetrics.stream()
            .filter(m -> m.getName().equals("disamb_bias_score_Age"))
            .findFirst()
            .orElseThrow();
    assertEquals(1, biasScoreMetric.getGuardrails().size());
    assertEquals(1L, biasScoreMetric.getGuardrails().get(0));

    var crowsPairsTask =
        tasks.stream()
            .filter(t -> t.getName().equals("crows_pairs_english"))
            .findFirst()
            .orElseThrow();
    var crowsPairsMetrics = crowsPairsTask.getMetrics();
    assertEquals(1, crowsPairsMetrics.size());
    var pctStereotypeMetric =
        crowsPairsMetrics.stream()
            .filter(m -> m.getName().equals("pct_stereotype"))
            .findFirst()
            .orElseThrow();
    assertEquals(2, pctStereotypeMetric.getGuardrails().size());
    assertTrue(pctStereotypeMetric.getGuardrails().containsAll(List.of(1L, 2L)));

    var guardrails = report.getGuardrails();
    assertNotNull(guardrails);
    assertEquals(2, guardrails.size());

    var guardrail = guardrails.get(0);
    assertEquals("Guardrails.ai", guardrail.getName());

    guardrail = guardrails.get(1);
    assertEquals("NeMo Guardrails", guardrail.getName());
  }

  @Test
  public void testGet_NotFound() {
    var report = service.get(UUID.fromString("123e4567-e89b-12d3-a456-426614174000"));
    assertNull(report);
  }

  @Test
  public void testGet_Null() {
    var report = service.get(null);
    assertNull(report);
  }
}
