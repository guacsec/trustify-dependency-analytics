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

/** Model card response */
@JsonPropertyOrder({
  ModelCardResponse.JSON_PROPERTY_ID,
  ModelCardResponse.JSON_PROPERTY_NAME,
  ModelCardResponse.JSON_PROPERTY_SOURCE,
  ModelCardResponse.JSON_PROPERTY_CONFIG,
  ModelCardResponse.JSON_PROPERTY_TASKS,
  ModelCardResponse.JSON_PROPERTY_GUARDRAILS
})
@jakarta.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class ModelCardResponse implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String JSON_PROPERTY_ID = "id";
  private String id;

  public static final String JSON_PROPERTY_NAME = "name";
  private String name;

  public static final String JSON_PROPERTY_SOURCE = "source";
  private String source;

  public static final String JSON_PROPERTY_CONFIG = "config";
  private ReportConfig config;

  public static final String JSON_PROPERTY_TASKS = "tasks";
  private List<ReportTask> tasks;

  public static final String JSON_PROPERTY_GUARDRAILS = "guardrails";
  private List<Guardrail> guardrails;

  public ModelCardResponse() {}

  public ModelCardResponse id(String id) {
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

  public ModelCardResponse name(String name) {
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

  public ModelCardResponse source(String source) {
    this.source = source;
    return this;
  }

  /**
   * Source of the model
   *
   * @return source
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_SOURCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getSource() {
    return source;
  }

  @JsonProperty(JSON_PROPERTY_SOURCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSource(String source) {
    this.source = source;
  }

  public ModelCardResponse config(ReportConfig config) {
    this.config = config;
    return this;
  }

  /**
   * Get config
   *
   * @return config
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_CONFIG)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public ReportConfig getConfig() {
    return config;
  }

  @JsonProperty(JSON_PROPERTY_CONFIG)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setConfig(ReportConfig config) {
    this.config = config;
  }

  public ModelCardResponse tasks(List<ReportTask> tasks) {
    this.tasks = tasks;
    return this;
  }

  public ModelCardResponse addTasksItem(ReportTask tasksItem) {
    if (this.tasks == null) {
      this.tasks = new ArrayList<>();
    }
    this.tasks.add(tasksItem);
    return this;
  }

  /**
   * Get tasks
   *
   * @return tasks
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_TASKS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<ReportTask> getTasks() {
    return tasks;
  }

  @JsonProperty(JSON_PROPERTY_TASKS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setTasks(List<ReportTask> tasks) {
    this.tasks = tasks;
  }

  public ModelCardResponse guardrails(List<Guardrail> guardrails) {
    this.guardrails = guardrails;
    return this;
  }

  public ModelCardResponse addGuardrailsItem(Guardrail guardrailsItem) {
    if (this.guardrails == null) {
      this.guardrails = new ArrayList<>();
    }
    this.guardrails.add(guardrailsItem);
    return this;
  }

  /**
   * Get guardrails
   *
   * @return guardrails
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_GUARDRAILS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<Guardrail> getGuardrails() {
    return guardrails;
  }

  @JsonProperty(JSON_PROPERTY_GUARDRAILS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setGuardrails(List<Guardrail> guardrails) {
    this.guardrails = guardrails;
  }

  /** Return true if this ModelCardResponse object is equal to o. */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ModelCardResponse modelCardResponse = (ModelCardResponse) o;
    return Objects.equals(this.id, modelCardResponse.id)
        && Objects.equals(this.name, modelCardResponse.name)
        && Objects.equals(this.source, modelCardResponse.source)
        && Objects.equals(this.config, modelCardResponse.config)
        && Objects.equals(this.tasks, modelCardResponse.tasks)
        && Objects.equals(this.guardrails, modelCardResponse.guardrails);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, name, source, config, tasks, guardrails);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ModelCardResponse {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    source: ").append(toIndentedString(source)).append("\n");
    sb.append("    config: ").append(toIndentedString(config)).append("\n");
    sb.append("    tasks: ").append(toIndentedString(tasks)).append("\n");
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

    // add `source` to the URL query string
    if (getSource() != null) {
      joiner.add(
          String.format(
              "%ssource%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getSource()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `config` to the URL query string
    if (getConfig() != null) {
      joiner.add(getConfig().toUrlQueryString(prefix + "config" + suffix));
    }

    // add `tasks` to the URL query string
    if (getTasks() != null) {
      for (int i = 0; i < getTasks().size(); i++) {
        if (getTasks().get(i) != null) {
          joiner.add(
              getTasks()
                  .get(i)
                  .toUrlQueryString(
                      String.format(
                          "%stasks%s%s",
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
        if (getGuardrails().get(i) != null) {
          joiner.add(
              getGuardrails()
                  .get(i)
                  .toUrlQueryString(
                      String.format(
                          "%sguardrails%s%s",
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
