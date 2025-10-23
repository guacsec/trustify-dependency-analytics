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

package io.github.guacsec.trustifyda.model.modelcards.api;

import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.StringJoiner;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/** MetricSummary */
@JsonPropertyOrder({
  MetricSummary.JSON_PROPERTY_TASK,
  MetricSummary.JSON_PROPERTY_METRIC,
  MetricSummary.JSON_PROPERTY_SCORE,
  MetricSummary.JSON_PROPERTY_ASSESSMENT
})
@jakarta.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class MetricSummary implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String JSON_PROPERTY_TASK = "task";
  private String task;

  public static final String JSON_PROPERTY_METRIC = "metric";
  private String metric;

  public static final String JSON_PROPERTY_SCORE = "score";
  private Float score;

  public static final String JSON_PROPERTY_ASSESSMENT = "assessment";
  private String assessment;

  public MetricSummary() {}

  public MetricSummary task(String task) {
    this.task = task;
    return this;
  }

  /**
   * Task name evaluated
   *
   * @return task
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_TASK)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getTask() {
    return task;
  }

  @JsonProperty(JSON_PROPERTY_TASK)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setTask(String task) {
    this.task = task;
  }

  public MetricSummary metric(String metric) {
    this.metric = metric;
    return this;
  }

  /**
   * Metric name evaluated
   *
   * @return metric
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_METRIC)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getMetric() {
    return metric;
  }

  @JsonProperty(JSON_PROPERTY_METRIC)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMetric(String metric) {
    this.metric = metric;
  }

  public MetricSummary score(Float score) {
    this.score = score;
    return this;
  }

  /**
   * Floating point score between 0 and 1 minimum: 0 maximum: 1
   *
   * @return score
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_SCORE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Float getScore() {
    return score;
  }

  @JsonProperty(JSON_PROPERTY_SCORE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setScore(Float score) {
    this.score = score;
  }

  public MetricSummary assessment(String assessment) {
    this.assessment = assessment;
    return this;
  }

  /**
   * Category of how the metric is evaluated
   *
   * @return assessment
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_ASSESSMENT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getAssessment() {
    return assessment;
  }

  @JsonProperty(JSON_PROPERTY_ASSESSMENT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAssessment(String assessment) {
    this.assessment = assessment;
  }

  /** Return true if this MetricSummary object is equal to o. */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MetricSummary metricSummary = (MetricSummary) o;
    return Objects.equals(this.task, metricSummary.task)
        && Objects.equals(this.metric, metricSummary.metric)
        && Objects.equals(this.score, metricSummary.score)
        && Objects.equals(this.assessment, metricSummary.assessment);
  }

  @Override
  public int hashCode() {
    return Objects.hash(task, metric, score, assessment);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class MetricSummary {\n");
    sb.append("    task: ").append(toIndentedString(task)).append("\n");
    sb.append("    metric: ").append(toIndentedString(metric)).append("\n");
    sb.append("    score: ").append(toIndentedString(score)).append("\n");
    sb.append("    assessment: ").append(toIndentedString(assessment)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

  /**
   * Convert the instance into URL query string.
   *
   * @return URL query string
   */
  public String toUrlQueryString() {
    return toUrlQueryString(null);
  }

  /**
   * Convert the instance into URL query string.
   *
   * @param prefix prefix of the query string
   * @return URL query string
   */
  public String toUrlQueryString(String prefix) {
    String suffix = "";
    String containerSuffix = "";
    String containerPrefix = "";
    if (prefix == null) {
      // style=form, explode=true, e.g. /pet?name=cat&type=manx
      prefix = "";
    } else {
      // deepObject style e.g. /pet?id[name]=cat&id[type]=manx
      prefix = prefix + "[";
      suffix = "]";
      containerSuffix = "]";
      containerPrefix = "[";
    }

    StringJoiner joiner = new StringJoiner("&");

    // add `task` to the URL query string
    if (getTask() != null) {
      joiner.add(
          String.format(
              "%stask%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getTask()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `metric` to the URL query string
    if (getMetric() != null) {
      joiner.add(
          String.format(
              "%smetric%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getMetric()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `score` to the URL query string
    if (getScore() != null) {
      joiner.add(
          String.format(
              "%sscore%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getScore()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `assessment` to the URL query string
    if (getAssessment() != null) {
      joiner.add(
          String.format(
              "%sassessment%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getAssessment()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    return joiner.toString();
  }
}
