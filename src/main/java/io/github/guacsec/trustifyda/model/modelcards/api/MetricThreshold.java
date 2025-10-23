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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

/** MetricThreshold */
@JsonPropertyOrder({
  MetricThreshold.JSON_PROPERTY_IMPACT,
  MetricThreshold.JSON_PROPERTY_CATEGORY,
  MetricThreshold.JSON_PROPERTY_INTERPRETATION,
  MetricThreshold.JSON_PROPERTY_UPPER,
  MetricThreshold.JSON_PROPERTY_LOWER
})
@jakarta.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class MetricThreshold implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Gets or Sets impact */
  public enum ImpactEnum {
    NO_MEASURABLE("no_measurable"),

    VERY_LOW("very_low"),

    LOW("low"),

    MODERATE("moderate"),

    HIGH("high"),

    SEVERE("severe");

    private String value;

    ImpactEnum(String value) {
      this.value = value;
    }

    @JsonValue
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static ImpactEnum fromValue(String value) {
      for (ImpactEnum b : ImpactEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_IMPACT = "impact";
  private ImpactEnum impact;

  public static final String JSON_PROPERTY_CATEGORY = "category";
  private Integer category;

  public static final String JSON_PROPERTY_INTERPRETATION = "interpretation";
  private String interpretation;

  public static final String JSON_PROPERTY_UPPER = "upper";
  private Float upper;

  public static final String JSON_PROPERTY_LOWER = "lower";
  private Float lower;

  public MetricThreshold() {}

  public MetricThreshold impact(ImpactEnum impact) {
    this.impact = impact;
    return this;
  }

  /**
   * Get impact
   *
   * @return impact
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_IMPACT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public ImpactEnum getImpact() {
    return impact;
  }

  @JsonProperty(JSON_PROPERTY_IMPACT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setImpact(ImpactEnum impact) {
    this.impact = impact;
  }

  public MetricThreshold category(Integer category) {
    this.category = category;
    return this;
  }

  /**
   * Get category
   *
   * @return category
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_CATEGORY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Integer getCategory() {
    return category;
  }

  @JsonProperty(JSON_PROPERTY_CATEGORY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCategory(Integer category) {
    this.category = category;
  }

  public MetricThreshold interpretation(String interpretation) {
    this.interpretation = interpretation;
    return this;
  }

  /**
   * Get interpretation
   *
   * @return interpretation
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_INTERPRETATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getInterpretation() {
    return interpretation;
  }

  @JsonProperty(JSON_PROPERTY_INTERPRETATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setInterpretation(String interpretation) {
    this.interpretation = interpretation;
  }

  public MetricThreshold upper(Float upper) {
    this.upper = upper;
    return this;
  }

  /**
   * Get upper minimum: 0 maximum: 1
   *
   * @return upper
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_UPPER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Float getUpper() {
    return upper;
  }

  @JsonProperty(JSON_PROPERTY_UPPER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setUpper(Float upper) {
    this.upper = upper;
  }

  public MetricThreshold lower(Float lower) {
    this.lower = lower;
    return this;
  }

  /**
   * Get lower minimum: 0 maximum: 1
   *
   * @return lower
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_LOWER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Float getLower() {
    return lower;
  }

  @JsonProperty(JSON_PROPERTY_LOWER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLower(Float lower) {
    this.lower = lower;
  }

  /** Return true if this MetricThreshold object is equal to o. */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MetricThreshold metricThreshold = (MetricThreshold) o;
    return Objects.equals(this.impact, metricThreshold.impact)
        && Objects.equals(this.category, metricThreshold.category)
        && Objects.equals(this.interpretation, metricThreshold.interpretation)
        && Objects.equals(this.upper, metricThreshold.upper)
        && Objects.equals(this.lower, metricThreshold.lower);
  }

  @Override
  public int hashCode() {
    return Objects.hash(impact, category, interpretation, upper, lower);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class MetricThreshold {\n");
    sb.append("    impact: ").append(toIndentedString(impact)).append("\n");
    sb.append("    category: ").append(toIndentedString(category)).append("\n");
    sb.append("    interpretation: ").append(toIndentedString(interpretation)).append("\n");
    sb.append("    upper: ").append(toIndentedString(upper)).append("\n");
    sb.append("    lower: ").append(toIndentedString(lower)).append("\n");
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

    // add `impact` to the URL query string
    if (getImpact() != null) {
      joiner.add(
          String.format(
              "%simpact%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getImpact()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `category` to the URL query string
    if (getCategory() != null) {
      joiner.add(
          String.format(
              "%scategory%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getCategory()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `interpretation` to the URL query string
    if (getInterpretation() != null) {
      joiner.add(
          String.format(
              "%sinterpretation%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getInterpretation()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `upper` to the URL query string
    if (getUpper() != null) {
      joiner.add(
          String.format(
              "%supper%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getUpper()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `lower` to the URL query string
    if (getLower() != null) {
      joiner.add(
          String.format(
              "%slower%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getLower()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    return joiner.toString();
  }
}
