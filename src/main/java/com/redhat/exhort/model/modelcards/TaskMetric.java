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

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name = "task_metric")
@JsonPropertyOrder({"id", "name", "higherIsBetter", "categories", "thresholds"})
public class TaskMetric {

  @Id @GeneratedValue public Long id;

  @Column(name = "name")
  public String name;

  @ManyToOne
  @JoinColumn(name = "task_definition_id")
  @JsonBackReference
  public TaskDefinition taskDefinition;

  @Column(name = "higher_is_better")
  public Boolean higherIsBetter;

  @OneToMany(cascade = CascadeType.ALL)
  @JoinColumn(name = "task_metric_id")
  @JsonManagedReference
  public List<Threshold> thresholds;

  public Set<String> categories;
}
