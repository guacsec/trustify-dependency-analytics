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

/** ReportMetric */
@JsonPropertyOrder({
  ReportMetric.JSON_PROPERTY_NAME,
  ReportMetric.JSON_PROPERTY_CATEGORIES,
  ReportMetric.JSON_PROPERTY_HIGHER_IS_BETTER,
  ReportMetric.JSON_PROPERTY_SCORE,
  ReportMetric.JSON_PROPERTY_THRESHOLDS,
  ReportMetric.JSON_PROPERTY_GUARDRAILS
})
@jakarta.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class ReportMetric implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String JSON_PROPERTY_NAME = "name";
  private String name;

  public static final String JSON_PROPERTY_CATEGORIES = "categories";
  private List<String> categories;

  public static final String JSON_PROPERTY_HIGHER_IS_BETTER = "higher_is_better";
  private Boolean higherIsBetter;

  public static final String JSON_PROPERTY_SCORE = "score";
  private Float score;

  public static final String JSON_PROPERTY_THRESHOLDS = "thresholds";
  private List<MetricThreshold> thresholds;

  public static final String JSON_PROPERTY_GUARDRAILS = "guardrails";
  private List<Long> guardrails;

  public ReportMetric() {}

  public ReportMetric name(String name) {
    this.name = name;
    return this;
  }

  /**
   * Get name
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

  public ReportMetric categories(List<String> categories) {
    this.categories = categories;
    return this;
  }

  public ReportMetric addCategoriesItem(String categoriesItem) {
    if (this.categories == null) {
      this.categories = new ArrayList<>();
    }
    this.categories.add(categoriesItem);
    return this;
  }

  /**
   * Get categories
   *
   * @return categories
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_CATEGORIES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<String> getCategories() {
    return categories;
  }

  @JsonProperty(JSON_PROPERTY_CATEGORIES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCategories(List<String> categories) {
    this.categories = categories;
  }

  public ReportMetric higherIsBetter(Boolean higherIsBetter) {
    this.higherIsBetter = higherIsBetter;
    return this;
  }

  /**
   * Get higherIsBetter
   *
   * @return higherIsBetter
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_HIGHER_IS_BETTER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getHigherIsBetter() {
    return higherIsBetter;
  }

  @JsonProperty(JSON_PROPERTY_HIGHER_IS_BETTER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setHigherIsBetter(Boolean higherIsBetter) {
    this.higherIsBetter = higherIsBetter;
  }

  public ReportMetric score(Float score) {
    this.score = score;
    return this;
  }

  /**
   * Get score minimum: 0 maximum: 1
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

  public ReportMetric thresholds(List<MetricThreshold> thresholds) {
    this.thresholds = thresholds;
    return this;
  }

  public ReportMetric addThresholdsItem(MetricThreshold thresholdsItem) {
    if (this.thresholds == null) {
      this.thresholds = new ArrayList<>();
    }
    this.thresholds.add(thresholdsItem);
    return this;
  }

  /**
   * Get thresholds
   *
   * @return thresholds
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_THRESHOLDS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<MetricThreshold> getThresholds() {
    return thresholds;
  }

  @JsonProperty(JSON_PROPERTY_THRESHOLDS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setThresholds(List<MetricThreshold> thresholds) {
    this.thresholds = thresholds;
  }

  public ReportMetric guardrails(List<Long> guardrails) {
    this.guardrails = guardrails;
    return this;
  }

  public ReportMetric addGuardrailsItem(Long guardrailsItem) {
    if (this.guardrails == null) {
      this.guardrails = new ArrayList<>();
    }
    this.guardrails.add(guardrailsItem);
    return this;
  }

  /**
   * Guardrail IDs that are recommended to be used to improve the metric score
   *
   * @return guardrails
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_GUARDRAILS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<Long> getGuardrails() {
    return guardrails;
  }

  @JsonProperty(JSON_PROPERTY_GUARDRAILS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setGuardrails(List<Long> guardrails) {
    this.guardrails = guardrails;
  }

  /** Return true if this ReportMetric object is equal to o. */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ReportMetric reportMetric = (ReportMetric) o;
    return Objects.equals(this.name, reportMetric.name)
        && Objects.equals(this.categories, reportMetric.categories)
        && Objects.equals(this.higherIsBetter, reportMetric.higherIsBetter)
        && Objects.equals(this.score, reportMetric.score)
        && Objects.equals(this.thresholds, reportMetric.thresholds)
        && Objects.equals(this.guardrails, reportMetric.guardrails);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, categories, higherIsBetter, score, thresholds, guardrails);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ReportMetric {\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    categories: ").append(toIndentedString(categories)).append("\n");
    sb.append("    higherIsBetter: ").append(toIndentedString(higherIsBetter)).append("\n");
    sb.append("    score: ").append(toIndentedString(score)).append("\n");
    sb.append("    thresholds: ").append(toIndentedString(thresholds)).append("\n");
    sb.append("    guardrails: ").append(toIndentedString(guardrails)).append("\n");
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

    // add `categories` to the URL query string
    if (getCategories() != null) {
      for (int i = 0; i < getCategories().size(); i++) {
        joiner.add(
            String.format(
                "%scategories%s%s=%s",
                prefix,
                suffix,
                "".equals(suffix)
                    ? ""
                    : String.format("%s%d%s", containerPrefix, i, containerSuffix),
                URLEncoder.encode(String.valueOf(getCategories().get(i)), StandardCharsets.UTF_8)
                    .replaceAll("\\+", "%20")));
      }
    }

    // add `higher_is_better` to the URL query string
    if (getHigherIsBetter() != null) {
      joiner.add(
          String.format(
              "%shigher_is_better%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getHigherIsBetter()), StandardCharsets.UTF_8)
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

    // add `thresholds` to the URL query string
    if (getThresholds() != null) {
      for (int i = 0; i < getThresholds().size(); i++) {
        if (getThresholds().get(i) != null) {
          joiner.add(
              getThresholds()
                  .get(i)
                  .toUrlQueryString(
                      String.format(
                          "%sthresholds%s%s",
                          prefix,
                          suffix,
                          "".equals(suffix)
                              ? ""
                              : String.format("%s%d%s", containerPrefix, i, containerSuffix))));
        }
      }
    }

    // add `guardrails` to the URL query string
    if (getGuardrails() != null) {
      for (int i = 0; i < getGuardrails().size(); i++) {
        joiner.add(
            String.format(
                "%sguardrails%s%s=%s",
                prefix,
                suffix,
                "".equals(suffix)
                    ? ""
                    : String.format("%s%d%s", containerPrefix, i, containerSuffix),
                URLEncoder.encode(String.valueOf(getGuardrails().get(i)), StandardCharsets.UTF_8)
                    .replaceAll("\\+", "%20")));
      }
    }

    return joiner.toString();
  }
}
