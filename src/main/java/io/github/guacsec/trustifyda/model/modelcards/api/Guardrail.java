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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

/** Guardrail */
@JsonPropertyOrder({
  Guardrail.JSON_PROPERTY_ID,
  Guardrail.JSON_PROPERTY_NAME,
  Guardrail.JSON_PROPERTY_DESCRIPTION,
  Guardrail.JSON_PROPERTY_METADATA_KEYS,
  Guardrail.JSON_PROPERTY_SCOPE,
  Guardrail.JSON_PROPERTY_EXTERNAL_REFERENCES,
  Guardrail.JSON_PROPERTY_INSTRUCTIONS
})
@jakarta.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class Guardrail implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String JSON_PROPERTY_ID = "id";
  private Long id;

  public static final String JSON_PROPERTY_NAME = "name";
  private String name;

  public static final String JSON_PROPERTY_DESCRIPTION = "description";
  private String description;

  public static final String JSON_PROPERTY_METADATA_KEYS = "metadata_keys";
  private List<String> metadataKeys;

  /** Gets or Sets scope */
  public enum ScopeEnum {
    INPUT("input"),

    OUTPUT("output"),

    BOTH("both");

    private String value;

    ScopeEnum(String value) {
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
    public static ScopeEnum fromValue(String value) {
      for (ScopeEnum b : ScopeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_SCOPE = "scope";
  private ScopeEnum scope;

  public static final String JSON_PROPERTY_EXTERNAL_REFERENCES = "external_references";
  private List<String> externalReferences;

  public static final String JSON_PROPERTY_INSTRUCTIONS = "instructions";
  private String instructions;

  public Guardrail() {}

  public Guardrail id(Long id) {
    this.id = id;
    return this;
  }

  /**
   * Unique identifier for the guardrail
   *
   * @return id
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Long getId() {
    return id;
  }

  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setId(Long id) {
    this.id = id;
  }

  public Guardrail name(String name) {
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

  public Guardrail description(String description) {
    this.description = description;
    return this;
  }

  /**
   * Get description
   *
   * @return description
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getDescription() {
    return description;
  }

  @JsonProperty(JSON_PROPERTY_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDescription(String description) {
    this.description = description;
  }

  public Guardrail metadataKeys(List<String> metadataKeys) {
    this.metadataKeys = metadataKeys;
    return this;
  }

  public Guardrail addMetadataKeysItem(String metadataKeysItem) {
    if (this.metadataKeys == null) {
      this.metadataKeys = new ArrayList<>();
    }
    this.metadataKeys.add(metadataKeysItem);
    return this;
  }

  /**
   * Get metadataKeys
   *
   * @return metadataKeys
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_METADATA_KEYS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<String> getMetadataKeys() {
    return metadataKeys;
  }

  @JsonProperty(JSON_PROPERTY_METADATA_KEYS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMetadataKeys(List<String> metadataKeys) {
    this.metadataKeys = metadataKeys;
  }

  public Guardrail scope(ScopeEnum scope) {
    this.scope = scope;
    return this;
  }

  /**
   * Get scope
   *
   * @return scope
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_SCOPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public ScopeEnum getScope() {
    return scope;
  }

  @JsonProperty(JSON_PROPERTY_SCOPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setScope(ScopeEnum scope) {
    this.scope = scope;
  }

  public Guardrail externalReferences(List<String> externalReferences) {
    this.externalReferences = externalReferences;
    return this;
  }

  public Guardrail addExternalReferencesItem(String externalReferencesItem) {
    if (this.externalReferences == null) {
      this.externalReferences = new ArrayList<>();
    }
    this.externalReferences.add(externalReferencesItem);
    return this;
  }

  /**
   * Get externalReferences
   *
   * @return externalReferences
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_EXTERNAL_REFERENCES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<String> getExternalReferences() {
    return externalReferences;
  }

  @JsonProperty(JSON_PROPERTY_EXTERNAL_REFERENCES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setExternalReferences(List<String> externalReferences) {
    this.externalReferences = externalReferences;
  }

  public Guardrail instructions(String instructions) {
    this.instructions = instructions;
    return this;
  }

  /**
   * Get instructions
   *
   * @return instructions
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_INSTRUCTIONS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getInstructions() {
    return instructions;
  }

  @JsonProperty(JSON_PROPERTY_INSTRUCTIONS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setInstructions(String instructions) {
    this.instructions = instructions;
  }

  /** Return true if this Guardrail object is equal to o. */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Guardrail guardrail = (Guardrail) o;
    return Objects.equals(this.id, guardrail.id)
        && Objects.equals(this.name, guardrail.name)
        && Objects.equals(this.description, guardrail.description)
        && Objects.equals(this.metadataKeys, guardrail.metadataKeys)
        && Objects.equals(this.scope, guardrail.scope)
        && Objects.equals(this.externalReferences, guardrail.externalReferences)
        && Objects.equals(this.instructions, guardrail.instructions);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        id, name, description, metadataKeys, scope, externalReferences, instructions);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Guardrail {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    metadataKeys: ").append(toIndentedString(metadataKeys)).append("\n");
    sb.append("    scope: ").append(toIndentedString(scope)).append("\n");
    sb.append("    externalReferences: ").append(toIndentedString(externalReferences)).append("\n");
    sb.append("    instructions: ").append(toIndentedString(instructions)).append("\n");
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

    // add `description` to the URL query string
    if (getDescription() != null) {
      joiner.add(
          String.format(
              "%sdescription%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getDescription()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `metadata_keys` to the URL query string
    if (getMetadataKeys() != null) {
      for (int i = 0; i < getMetadataKeys().size(); i++) {
        joiner.add(
            String.format(
                "%smetadata_keys%s%s=%s",
                prefix,
                suffix,
                "".equals(suffix)
                    ? ""
                    : String.format("%s%d%s", containerPrefix, i, containerSuffix),
                URLEncoder.encode(String.valueOf(getMetadataKeys().get(i)), StandardCharsets.UTF_8)
                    .replaceAll("\\+", "%20")));
      }
    }

    // add `scope` to the URL query string
    if (getScope() != null) {
      joiner.add(
          String.format(
              "%sscope%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getScope()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `external_references` to the URL query string
    if (getExternalReferences() != null) {
      for (int i = 0; i < getExternalReferences().size(); i++) {
        joiner.add(
            String.format(
                "%sexternal_references%s%s=%s",
                prefix,
                suffix,
                "".equals(suffix)
                    ? ""
                    : String.format("%s%d%s", containerPrefix, i, containerSuffix),
                URLEncoder.encode(
                        String.valueOf(getExternalReferences().get(i)), StandardCharsets.UTF_8)
                    .replaceAll("\\+", "%20")));
      }
    }

    // add `instructions` to the URL query string
    if (getInstructions() != null) {
      joiner.add(
          String.format(
              "%sinstructions%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getInstructions()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    return joiner.toString();
  }
}
