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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.StringJoiner;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/** ListModelCardResponse */
@JsonPropertyOrder({
  ListModelCardResponse.JSON_PROPERTY_ID,
  ListModelCardResponse.JSON_PROPERTY_NAME,
  ListModelCardResponse.JSON_PROPERTY_MODEL_NAME,
  ListModelCardResponse.JSON_PROPERTY_METRICS
})
@jakarta.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class ListModelCardResponse implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String JSON_PROPERTY_ID = "id";
  private String id;

  public static final String JSON_PROPERTY_NAME = "name";
  private String name;

  public static final String JSON_PROPERTY_MODEL_NAME = "model_name";
  private String modelName;

  public static final String JSON_PROPERTY_METRICS = "metrics";
  private List<MetricSummary> metrics;

  public ListModelCardResponse() {}

  public ListModelCardResponse id(String id) {
    this.id = id;
    return this;
  }

  /**
   * Unique identifier for the model card
   *
   * @return id
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getId() {
    return id;
  }

  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setId(String id) {
    this.id = id;
  }

  public ListModelCardResponse name(String name) {
    this.name = name;
    return this;
  }

  /**
   * Name of the report
   *
   * @return name
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getName() {
    return name;
  }

  @JsonProperty(JSON_PROPERTY_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setName(String name) {
    this.name = name;
  }

  public ListModelCardResponse modelName(String modelName) {
    this.modelName = modelName;
    return this;
  }

  /**
   * Name of the model
   *
   * @return modelName
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_MODEL_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getModelName() {
    return modelName;
  }

  @JsonProperty(JSON_PROPERTY_MODEL_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setModelName(String modelName) {
    this.modelName = modelName;
  }

  public ListModelCardResponse metrics(List<MetricSummary> metrics) {
    this.metrics = metrics;
    return this;
  }

  public ListModelCardResponse addMetricsItem(MetricSummary metricsItem) {
    if (this.metrics == null) {
      this.metrics = new ArrayList<>();
    }
    this.metrics.add(metricsItem);
    return this;
  }

  /**
   * Get metrics
   *
   * @return metrics
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_METRICS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<MetricSummary> getMetrics() {
    return metrics;
  }

  @JsonProperty(JSON_PROPERTY_METRICS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMetrics(List<MetricSummary> metrics) {
    this.metrics = metrics;
  }

  /** Return true if this ListModelCardResponse object is equal to o. */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ListModelCardResponse listModelCardResponse = (ListModelCardResponse) o;
    return Objects.equals(this.id, listModelCardResponse.id)
        && Objects.equals(this.name, listModelCardResponse.name)
        && Objects.equals(this.modelName, listModelCardResponse.modelName)
        && Objects.equals(this.metrics, listModelCardResponse.metrics);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, name, modelName, metrics);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ListModelCardResponse {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    modelName: ").append(toIndentedString(modelName)).append("\n");
    sb.append("    metrics: ").append(toIndentedString(metrics)).append("\n");
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

    // add `id` to the URL query string
    if (getId() != null) {
      joiner.add(
          String.format(
              "%sid%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getId()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `name` to the URL query string
    if (getName() != null) {
      joiner.add(
          String.format(
              "%sname%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getName()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `model_name` to the URL query string
    if (getModelName() != null) {
      joiner.add(
          String.format(
              "%smodel_name%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getModelName()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `metrics` to the URL query string
    if (getMetrics() != null) {
      for (int i = 0; i < getMetrics().size(); i++) {
        if (getMetrics().get(i) != null) {
          joiner.add(
              getMetrics()
                  .get(i)
                  .toUrlQueryString(
                      String.format(
                          "%smetrics%s%s",
                          prefix,
                          suffix,
                          "".equals(suffix)
                              ? ""
                              : String.format("%s%d%s", containerPrefix, i, containerSuffix))));
        }
      }
    }

    return joiner.toString();
  }
}
