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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/** ModelCardQueryItem */
@JsonPropertyOrder({
  ModelCardQueryItem.JSON_PROPERTY_MODEL_NAME,
  ModelCardQueryItem.JSON_PROPERTY_FILTER
})
@jakarta.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class ModelCardQueryItem implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String JSON_PROPERTY_MODEL_NAME = "model_name";
  private String modelName;

  public static final String JSON_PROPERTY_FILTER = "filter";
  private Map<String, String> filter = new HashMap<>();

  public ModelCardQueryItem() {}

  public ModelCardQueryItem modelName(String modelName) {
    this.modelName = modelName;
    return this;
  }

  /**
   * Get modelName
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

  public ModelCardQueryItem filter(Map<String, String> filter) {
    this.filter = filter;
    return this;
  }

  public ModelCardQueryItem putFilterItem(String key, String filterItem) {
    if (this.filter == null) {
      this.filter = new HashMap<>();
    }
    this.filter.put(key, filterItem);
    return this;
  }

  /**
   * Get filter
   *
   * @return filter
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_FILTER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Map<String, String> getFilter() {
    return filter;
  }

  @JsonProperty(JSON_PROPERTY_FILTER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setFilter(Map<String, String> filter) {
    this.filter = filter;
  }

  /** Return true if this ModelCardQueryItem object is equal to o. */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ModelCardQueryItem modelCardQueryItem = (ModelCardQueryItem) o;
    return Objects.equals(this.modelName, modelCardQueryItem.modelName)
        && Objects.equals(this.filter, modelCardQueryItem.filter);
  }

  @Override
  public int hashCode() {
    return Objects.hash(modelName, filter);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ModelCardQueryItem {\n");
    sb.append("    modelName: ").append(toIndentedString(modelName)).append("\n");
    sb.append("    filter: ").append(toIndentedString(filter)).append("\n");
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

    // add `filter` to the URL query string
    if (getFilter() != null) {
      for (String _key : getFilter().keySet()) {
        joiner.add(
            String.format(
                "%sfilter%s%s=%s",
                prefix,
                suffix,
                "".equals(suffix)
                    ? ""
                    : String.format("%s%d%s", containerPrefix, _key, containerSuffix),
                getFilter().get(_key),
                URLEncoder.encode(String.valueOf(getFilter().get(_key)), StandardCharsets.UTF_8)
                    .replaceAll("\\+", "%20")));
      }
    }

    return joiner.toString();
  }
}
