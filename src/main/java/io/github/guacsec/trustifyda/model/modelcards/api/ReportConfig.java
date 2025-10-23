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

/** ReportConfig */
@JsonPropertyOrder({
  ReportConfig.JSON_PROPERTY_MODEL_NAME,
  ReportConfig.JSON_PROPERTY_MODEL_SOURCE,
  ReportConfig.JSON_PROPERTY_MODEL_REVISION,
  ReportConfig.JSON_PROPERTY_MODEL_REVISION_SHA,
  ReportConfig.JSON_PROPERTY_DTYPE,
  ReportConfig.JSON_PROPERTY_BATCH_SIZE,
  ReportConfig.JSON_PROPERTY_BATCH_SIZES,
  ReportConfig.JSON_PROPERTY_LM_EVAL_VERSION,
  ReportConfig.JSON_PROPERTY_TRANSFORMERS_VERSION
})
@jakarta.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class ReportConfig implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String JSON_PROPERTY_MODEL_NAME = "model_name";
  private String modelName;

  public static final String JSON_PROPERTY_MODEL_SOURCE = "model_source";
  private String modelSource;

  public static final String JSON_PROPERTY_MODEL_REVISION = "model_revision";
  private String modelRevision;

  public static final String JSON_PROPERTY_MODEL_REVISION_SHA = "model_revision_sha";
  private String modelRevisionSha;

  public static final String JSON_PROPERTY_DTYPE = "dtype";
  private String dtype;

  public static final String JSON_PROPERTY_BATCH_SIZE = "batch_size";
  private String batchSize;

  public static final String JSON_PROPERTY_BATCH_SIZES = "batch_sizes";
  private List<Integer> batchSizes;

  public static final String JSON_PROPERTY_LM_EVAL_VERSION = "lm_eval_version";
  private String lmEvalVersion;

  public static final String JSON_PROPERTY_TRANSFORMERS_VERSION = "transformers_version";
  private String transformersVersion;

  public ReportConfig() {}

  public ReportConfig modelName(String modelName) {
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

  public ReportConfig modelSource(String modelSource) {
    this.modelSource = modelSource;
    return this;
  }

  /**
   * Get modelSource
   *
   * @return modelSource
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_MODEL_SOURCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getModelSource() {
    return modelSource;
  }

  @JsonProperty(JSON_PROPERTY_MODEL_SOURCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setModelSource(String modelSource) {
    this.modelSource = modelSource;
  }

  public ReportConfig modelRevision(String modelRevision) {
    this.modelRevision = modelRevision;
    return this;
  }

  /**
   * Get modelRevision
   *
   * @return modelRevision
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_MODEL_REVISION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getModelRevision() {
    return modelRevision;
  }

  @JsonProperty(JSON_PROPERTY_MODEL_REVISION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setModelRevision(String modelRevision) {
    this.modelRevision = modelRevision;
  }

  public ReportConfig modelRevisionSha(String modelRevisionSha) {
    this.modelRevisionSha = modelRevisionSha;
    return this;
  }

  /**
   * Get modelRevisionSha
   *
   * @return modelRevisionSha
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_MODEL_REVISION_SHA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getModelRevisionSha() {
    return modelRevisionSha;
  }

  @JsonProperty(JSON_PROPERTY_MODEL_REVISION_SHA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setModelRevisionSha(String modelRevisionSha) {
    this.modelRevisionSha = modelRevisionSha;
  }

  public ReportConfig dtype(String dtype) {
    this.dtype = dtype;
    return this;
  }

  /**
   * Get dtype
   *
   * @return dtype
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_DTYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getDtype() {
    return dtype;
  }

  @JsonProperty(JSON_PROPERTY_DTYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDtype(String dtype) {
    this.dtype = dtype;
  }

  public ReportConfig batchSize(String batchSize) {
    this.batchSize = batchSize;
    return this;
  }

  /**
   * Get batchSize
   *
   * @return batchSize
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_BATCH_SIZE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getBatchSize() {
    return batchSize;
  }

  @JsonProperty(JSON_PROPERTY_BATCH_SIZE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setBatchSize(String batchSize) {
    this.batchSize = batchSize;
  }

  public ReportConfig batchSizes(List<Integer> batchSizes) {
    this.batchSizes = batchSizes;
    return this;
  }

  public ReportConfig addBatchSizesItem(Integer batchSizesItem) {
    if (this.batchSizes == null) {
      this.batchSizes = new ArrayList<>();
    }
    this.batchSizes.add(batchSizesItem);
    return this;
  }

  /**
   * Get batchSizes
   *
   * @return batchSizes
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_BATCH_SIZES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<Integer> getBatchSizes() {
    return batchSizes;
  }

  @JsonProperty(JSON_PROPERTY_BATCH_SIZES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setBatchSizes(List<Integer> batchSizes) {
    this.batchSizes = batchSizes;
  }

  public ReportConfig lmEvalVersion(String lmEvalVersion) {
    this.lmEvalVersion = lmEvalVersion;
    return this;
  }

  /**
   * Get lmEvalVersion
   *
   * @return lmEvalVersion
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_LM_EVAL_VERSION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getLmEvalVersion() {
    return lmEvalVersion;
  }

  @JsonProperty(JSON_PROPERTY_LM_EVAL_VERSION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLmEvalVersion(String lmEvalVersion) {
    this.lmEvalVersion = lmEvalVersion;
  }

  public ReportConfig transformersVersion(String transformersVersion) {
    this.transformersVersion = transformersVersion;
    return this;
  }

  /**
   * Get transformersVersion
   *
   * @return transformersVersion
   */
  @jakarta.annotation.Nullable @JsonProperty(JSON_PROPERTY_TRANSFORMERS_VERSION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getTransformersVersion() {
    return transformersVersion;
  }

  @JsonProperty(JSON_PROPERTY_TRANSFORMERS_VERSION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setTransformersVersion(String transformersVersion) {
    this.transformersVersion = transformersVersion;
  }

  /** Return true if this ReportConfig object is equal to o. */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ReportConfig reportConfig = (ReportConfig) o;
    return Objects.equals(this.modelName, reportConfig.modelName)
        && Objects.equals(this.modelSource, reportConfig.modelSource)
        && Objects.equals(this.modelRevision, reportConfig.modelRevision)
        && Objects.equals(this.modelRevisionSha, reportConfig.modelRevisionSha)
        && Objects.equals(this.dtype, reportConfig.dtype)
        && Objects.equals(this.batchSize, reportConfig.batchSize)
        && Objects.equals(this.batchSizes, reportConfig.batchSizes)
        && Objects.equals(this.lmEvalVersion, reportConfig.lmEvalVersion)
        && Objects.equals(this.transformersVersion, reportConfig.transformersVersion);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        modelName,
        modelSource,
        modelRevision,
        modelRevisionSha,
        dtype,
        batchSize,
        batchSizes,
        lmEvalVersion,
        transformersVersion);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ReportConfig {\n");
    sb.append("    modelName: ").append(toIndentedString(modelName)).append("\n");
    sb.append("    modelSource: ").append(toIndentedString(modelSource)).append("\n");
    sb.append("    modelRevision: ").append(toIndentedString(modelRevision)).append("\n");
    sb.append("    modelRevisionSha: ").append(toIndentedString(modelRevisionSha)).append("\n");
    sb.append("    dtype: ").append(toIndentedString(dtype)).append("\n");
    sb.append("    batchSize: ").append(toIndentedString(batchSize)).append("\n");
    sb.append("    batchSizes: ").append(toIndentedString(batchSizes)).append("\n");
    sb.append("    lmEvalVersion: ").append(toIndentedString(lmEvalVersion)).append("\n");
    sb.append("    transformersVersion: ")
        .append(toIndentedString(transformersVersion))
        .append("\n");
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

    // add `model_source` to the URL query string
    if (getModelSource() != null) {
      joiner.add(
          String.format(
              "%smodel_source%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getModelSource()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `model_revision` to the URL query string
    if (getModelRevision() != null) {
      joiner.add(
          String.format(
              "%smodel_revision%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getModelRevision()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `model_revision_sha` to the URL query string
    if (getModelRevisionSha() != null) {
      joiner.add(
          String.format(
              "%smodel_revision_sha%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getModelRevisionSha()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `dtype` to the URL query string
    if (getDtype() != null) {
      joiner.add(
          String.format(
              "%sdtype%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getDtype()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `batch_size` to the URL query string
    if (getBatchSize() != null) {
      joiner.add(
          String.format(
              "%sbatch_size%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getBatchSize()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `batch_sizes` to the URL query string
    if (getBatchSizes() != null) {
      for (int i = 0; i < getBatchSizes().size(); i++) {
        joiner.add(
            String.format(
                "%sbatch_sizes%s%s=%s",
                prefix,
                suffix,
                "".equals(suffix)
                    ? ""
                    : String.format("%s%d%s", containerPrefix, i, containerSuffix),
                URLEncoder.encode(String.valueOf(getBatchSizes().get(i)), StandardCharsets.UTF_8)
                    .replaceAll("\\+", "%20")));
      }
    }

    // add `lm_eval_version` to the URL query string
    if (getLmEvalVersion() != null) {
      joiner.add(
          String.format(
              "%slm_eval_version%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getLmEvalVersion()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    // add `transformers_version` to the URL query string
    if (getTransformersVersion() != null) {
      joiner.add(
          String.format(
              "%stransformers_version%s=%s",
              prefix,
              suffix,
              URLEncoder.encode(String.valueOf(getTransformersVersion()), StandardCharsets.UTF_8)
                  .replaceAll("\\+", "%20")));
    }

    return joiner.toString();
  }
}
