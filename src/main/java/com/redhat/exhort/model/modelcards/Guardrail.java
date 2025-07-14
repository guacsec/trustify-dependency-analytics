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

package com.redhat.exhort.model.modelcards;

import java.util.List;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

@Entity
@Table(name = "guardrail")
public class Guardrail {

  @Id @GeneratedValue public Long id;

  public String name;

  public String description;

  @Enumerated(EnumType.STRING)
  public GuardrailScope scope;

  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
      name = "guardrail_metrics",
      joinColumns = @JoinColumn(name = "guardrail_id"),
      inverseJoinColumns = @JoinColumn(name = "task_metric_id"))
  public Set<TaskMetric> metrics;

  @Column(name = "external_references")
  public List<String> references;

  @Column(name = "metadata_keys")
  public List<String> metadataKeys;

  @Column(name = "instructions")
  public String instructions;
}
