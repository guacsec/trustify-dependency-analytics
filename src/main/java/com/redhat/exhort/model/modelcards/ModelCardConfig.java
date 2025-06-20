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

package com.redhat.exhort.model.modelcards;

import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

@Embeddable
public class ModelCardConfig {
  @Column(name = "model_name")
  public String modelName; // meta-llama/Llama-3.1-8B-Instruct

  @Column(name = "model_revision")
  public String modelRevision; // main

  @Column(name = "model_sha")
  public String modelSha; // sha256

  @Column(name = "model_source")
  public String modelSource; // hf

  @Column(name = "d_type")
  public String dType; // torch.float16

  @Column(name = "batch_size")
  public String batchSize; // auto

  @Column(name = "batch_sizes")
  public List<Integer> batchSizes; // [64]

  @Column(name = "lm_eval_version")
  public String lmEvalVersion; // 0.4.8

  @Column(name = "transformers_version")
  public String transformersVersion; // 4.51.3
}
