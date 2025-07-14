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

import java.util.List;

import com.redhat.exhort.model.modelcards.Guardrail;

import io.quarkus.hibernate.orm.panache.PanacheRepository;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class GuardrailRepository implements PanacheRepository<Guardrail> {

  public List<Guardrail> findByTaskMetricIds(List<Long> taskMetricIds) {
    return list(
        "SELECT DISTINCT g FROM Guardrail g JOIN g.metrics m WHERE m.id IN ?1", taskMetricIds);
  }
}
