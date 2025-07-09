/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.modelcards;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.redhat.exhort.api.v4.ModelCardQueryItem;

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
