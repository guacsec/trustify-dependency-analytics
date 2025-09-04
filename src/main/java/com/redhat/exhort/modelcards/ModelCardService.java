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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.redhat.exhort.api.v4.ListModelCardResponse;
import com.redhat.exhort.api.v4.MetricSummary;
import com.redhat.exhort.api.v4.MetricThreshold;
import com.redhat.exhort.api.v4.ModelCardQueryItem;
import com.redhat.exhort.api.v4.ModelCardResponse;
import com.redhat.exhort.api.v4.ReportConfig;
import com.redhat.exhort.api.v4.ReportMetric;
import com.redhat.exhort.api.v4.ReportTask;
import com.redhat.exhort.model.modelcards.Guardrail;
import com.redhat.exhort.model.modelcards.ModelCardConfig;
import com.redhat.exhort.model.modelcards.ModelCardReport;
import com.redhat.exhort.model.modelcards.ModelCardTask;
import com.redhat.exhort.model.modelcards.TaskMetric;
import com.redhat.exhort.model.modelcards.Threshold;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

@ApplicationScoped
public class ModelCardService {

  @Inject ModelCardRepository repository;

  @Inject GuardrailRepository guardrailRepository;

  @Transactional
  public ModelCardResponse get(UUID id) {
    var report = repository.findById(id);
    if (report == null) {
      return null;
    }
    List<Guardrail> guardrails = new ArrayList<>();
    if (report.tasks != null) {
      // Extract task metric IDs from the scores map
      List<Long> taskMetricIds =
          report.tasks.stream()
              .flatMap(task -> task.scores.keySet().stream())
              .map(metric -> metric.id)
              .distinct()
              .toList();

      if (!taskMetricIds.isEmpty()) {
        guardrails = guardrailRepository.findByTaskMetricIds(taskMetricIds);
      }
    }

    return toDto(report, guardrails);
  }

  @Transactional
  public List<ListModelCardResponse> find(List<ModelCardQueryItem> queries) {
    if (queries == null || queries.isEmpty()) {
      return Collections.emptyList();
    }
    List<String> names = queries.stream().map(ModelCardQueryItem::getModelName).toList();
    var reports = repository.find("config.modelName in (:names)", Map.of("names", names));
    if (reports == null) {
      return Collections.emptyList();
    }
    return reports.stream().map(this::toSummaryDto).collect(Collectors.toList());
  }

  private ModelCardResponse toDto(ModelCardReport entity, List<Guardrail> guardrails) {
    var dto = new ModelCardResponse();
    dto.id(entity.id.toString());
    dto.name(entity.name);
    dto.source(entity.source);
    dto.config(toConfigDto(entity.config));
    dto.tasks(
        entity.tasks != null
            ? entity.tasks.stream().map(t -> toTaskDto(t, guardrails)).toList()
            : null);
    dto.guardrails(guardrails.stream().map(this::toGuardrailDto).toList());
    return dto;
  }

  private ReportConfig toConfigDto(ModelCardConfig entity) {
    if (entity == null) return null;

    var dto = new ReportConfig();
    dto.modelName(entity.modelName);
    dto.modelRevision(entity.modelRevision);
    dto.modelRevisionSha(entity.modelSha);
    dto.modelSource(entity.modelSource);
    dto.dtype(entity.dType);
    dto.batchSize(entity.batchSize);
    dto.batchSizes(entity.batchSizes);
    dto.lmEvalVersion(entity.lmEvalVersion);
    dto.transformersVersion(entity.transformersVersion);
    return dto;
  }

  private ReportTask toTaskDto(ModelCardTask entity, List<Guardrail> guardrails) {
    if (entity == null) return null;

    var dto = new ReportTask();
    dto.name(entity.task.name);
    dto.description(entity.task.description);
    dto.tags(List.copyOf(entity.task.tags));
    dto.metrics(
        entity.scores.entrySet().stream()
            .map(s -> toMetricScoreDto(s, guardrails))
            .collect(Collectors.toList()));

    return dto;
  }

  private ReportMetric toMetricScoreDto(
      Map.Entry<TaskMetric, Float> e, List<Guardrail> guardrails) {
    var score = new ReportMetric();
    score.name(e.getKey().name);
    score.score(e.getValue());
    score.higherIsBetter(e.getKey().higherIsBetter);
    score.thresholds(
        e.getKey().thresholds != null
            ? e.getKey().thresholds.stream().map(this::toThresholdDto).toList()
            : null);
    var metricGuardrails =
        guardrails.stream()
            .filter(g -> g.metrics.contains(e.getKey()))
            .map(g -> g.id)
            .sorted()
            .toList();
    score.guardrails(metricGuardrails);
    score.categories(List.copyOf(e.getKey().categories));
    return score;
  }

  private MetricThreshold toThresholdDto(Threshold entity) {
    if (entity == null) return null;

    var dto = new MetricThreshold();
    dto.lower(entity.lower);
    dto.upper(entity.upper);
    dto.impact(entity.impact != null ? MetricThreshold.ImpactEnum.fromValue(entity.impact) : null);
    dto.interpretation(entity.interpretation);
    dto.category(entity.category);
    return dto;
  }

  private ListModelCardResponse toSummaryDto(ModelCardReport entity) {
    var dto = new ListModelCardResponse();
    dto.id(entity.id.toString());
    dto.name(entity.name);
    dto.modelName(entity.config.modelName);
    dto.metrics(entity.tasks.stream().flatMap(this::toMetricSummaryDto).toList());
    return dto;
  }

  private Stream<MetricSummary> toMetricSummaryDto(ModelCardTask entity) {
    return entity.scores.entrySet().stream()
        .map(
            e -> {
              var dto = new MetricSummary();
              dto.task(entity.task.name);
              dto.metric(e.getKey().name);
              dto.score(e.getValue());
              dto.assessment(getAssessment(e.getKey().thresholds, e.getValue()));
              return dto;
            });
  }

  private String getAssessment(List<Threshold> thresholds, Float score) {
    if (thresholds == null || thresholds.isEmpty()) {
      return null;
    }
    for (var t : thresholds) {
      if (score >= t.lower && score <= t.upper) {
        return t.impact;
      }
    }
    return null;
  }

  private com.redhat.exhort.api.v4.Guardrail toGuardrailDto(Guardrail entity) {
    var dto = new com.redhat.exhort.api.v4.Guardrail();
    dto.id(entity.id);
    dto.name(entity.name);
    dto.description(entity.description);
    dto.scope(com.redhat.exhort.api.v4.Guardrail.ScopeEnum.valueOf(entity.scope.name()));
    dto.externalReferences(entity.references);
    dto.metadataKeys(entity.metadataKeys);
    dto.instructions(entity.instructions);
    return dto;
  }
}
