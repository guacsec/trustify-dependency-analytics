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

package io.github.guacsec.trustifyda.model;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiConsumer;

import io.github.guacsec.trustifyda.api.v5.CvssVector;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class CvssParser {

  private static final record IndexItem(
      BiConsumer<String, CvssVector> setter, Map<String, String> parameters) {}

  private static final String V3_1 = "CVSS:3.1";
  private static final String V3_0 = "CVSS:3.0";

  private static final Map<String, IndexItem> INDEX = new HashMap<>();
  private static final Map<String, String> ATTACK_VECTORS = new HashMap<>();
  private static final Map<String, String> ATTACK_COMPLEXITY = new HashMap<>();
  private static final Map<String, String> PRIVILEGES_REQUIRED = new HashMap<>();
  private static final Map<String, String> USER_INTERACTION = new HashMap<>();
  private static final Map<String, String> SCOPE = new HashMap<>();
  private static final Map<String, String> IMPACT = new HashMap<>();
  private static final Map<String, String> EXPLOIT_CODE_MATURITY = new HashMap<>();
  private static final Map<String, String> REMEDIATION_LEVEL = new HashMap<>();
  private static final Map<String, String> REPORT_CONFIDENCE = new HashMap<>();

  private static final Map<String, IndexItem> INDEX_V2 = new HashMap<>();
  private static final Map<String, String> AUTHENTICATION_V2 = new HashMap<>();
  private static final Map<String, String> CONFIDENTIALITY_V2 = new HashMap<>();
  private static final Map<String, String> EXPLOIT_CODE_MATURITY_V2 = new HashMap<>();
  private static final Map<String, String> REMEDIATION_LEVEL_V2 = new HashMap<>();
  private static final Map<String, String> REPORT_CONFIDENCE_V2 = new HashMap<>();

  static {
    INDEX.put("AV", new IndexItem((v, b) -> b.attackVector(v), ATTACK_VECTORS));
    INDEX.put("AC", new IndexItem((v, b) -> b.attackComplexity(v), ATTACK_COMPLEXITY));
    INDEX.put("PR", new IndexItem((v, b) -> b.privilegesRequired(v), PRIVILEGES_REQUIRED));
    INDEX.put("UI", new IndexItem((v, b) -> b.userInteraction(v), USER_INTERACTION));
    INDEX.put("S", new IndexItem((v, b) -> b.scope(v), SCOPE));
    INDEX.put("C", new IndexItem((v, b) -> b.confidentialityImpact(v), IMPACT));
    INDEX.put("I", new IndexItem((v, b) -> b.integrityImpact(v), IMPACT));
    INDEX.put("A", new IndexItem((v, b) -> b.availabilityImpact(v), IMPACT));
    INDEX.put("E", new IndexItem((v, b) -> b.exploitCodeMaturity(v), EXPLOIT_CODE_MATURITY));
    INDEX.put("RL", new IndexItem((v, b) -> b.remediationLevel(v), REMEDIATION_LEVEL));
    INDEX.put("RC", new IndexItem((v, b) -> b.reportConfidence(v), REPORT_CONFIDENCE));

    ATTACK_VECTORS.put("N", "Network");
    ATTACK_VECTORS.put("A", "Adjacent Network");
    ATTACK_VECTORS.put("L", "Local");
    ATTACK_VECTORS.put("P", "Physical");

    ATTACK_COMPLEXITY.put("L", "Low");
    ATTACK_COMPLEXITY.put("H", "High");

    PRIVILEGES_REQUIRED.put("N", "None");
    PRIVILEGES_REQUIRED.put("L", "Low");
    PRIVILEGES_REQUIRED.put("H", "High");

    USER_INTERACTION.put("N", "None");
    USER_INTERACTION.put("R", "Required");

    SCOPE.put("U", "Unchanged");
    SCOPE.put("C", "Changed");

    IMPACT.put("N", "None");
    IMPACT.put("L", "Low");
    IMPACT.put("H", "High");

    EXPLOIT_CODE_MATURITY.put("X", "Not Defined");
    EXPLOIT_CODE_MATURITY.put("U", "Unproven that exploit exists");
    EXPLOIT_CODE_MATURITY.put("P", "Proof of concept code");
    EXPLOIT_CODE_MATURITY.put("F", "Functional exploit exists");
    EXPLOIT_CODE_MATURITY.put("H", "High");

    REMEDIATION_LEVEL.put("X", "Not Defined");
    REMEDIATION_LEVEL.put("O", "Official fix");
    REMEDIATION_LEVEL.put("T", "Temporary fix");
    REMEDIATION_LEVEL.put("W", "Workaround");
    REMEDIATION_LEVEL.put("U", "Unavailable");

    REPORT_CONFIDENCE.put("X", "Not Defined");
    REPORT_CONFIDENCE.put("U", "Unknown");
    REPORT_CONFIDENCE.put("R", "Reasonable");
    REPORT_CONFIDENCE.put("C", "Confirmed");

    INDEX_V2.put("AV", INDEX.get("AV"));
    INDEX_V2.put("AC", INDEX.get("AC"));
    INDEX_V2.put("Au", new IndexItem((v, b) -> b.privilegesRequired(v), AUTHENTICATION_V2));
    INDEX_V2.put("C", new IndexItem((v, b) -> b.confidentialityImpact(v), CONFIDENTIALITY_V2));
    INDEX_V2.put("I", new IndexItem((v, b) -> b.integrityImpact(v), CONFIDENTIALITY_V2));
    INDEX_V2.put("A", new IndexItem((v, b) -> b.availabilityImpact(v), CONFIDENTIALITY_V2));
    INDEX_V2.put("E", new IndexItem((v, b) -> b.exploitCodeMaturity(v), EXPLOIT_CODE_MATURITY_V2));
    INDEX_V2.put("RL", new IndexItem((v, b) -> b.remediationLevel(v), REMEDIATION_LEVEL_V2));
    INDEX_V2.put("RC", new IndexItem((v, b) -> b.reportConfidence(v), REPORT_CONFIDENCE_V2));

    AUTHENTICATION_V2.put("M", "High"); // Multiple -> High
    AUTHENTICATION_V2.put("S", "Low"); // Simple -> Low
    AUTHENTICATION_V2.put("N", "None");

    CONFIDENTIALITY_V2.put("P", "Low"); // Partial -> Low
    CONFIDENTIALITY_V2.put("C", "High"); // Complete -> High
    CONFIDENTIALITY_V2.put("N", "None");

    EXPLOIT_CODE_MATURITY_V2.put("ND", "Not Defined");
    EXPLOIT_CODE_MATURITY_V2.put("U", "Unproven that exploit exists");
    EXPLOIT_CODE_MATURITY_V2.put("P", "Proof of concept code");
    EXPLOIT_CODE_MATURITY_V2.put("F", "Functional exploit exists");
    EXPLOIT_CODE_MATURITY_V2.put("H", "High");

    REMEDIATION_LEVEL_V2.put("ND", "Not Defined");
    REMEDIATION_LEVEL_V2.put("OF", "Official fix");
    REMEDIATION_LEVEL_V2.put("TF", "Temporary fix");
    REMEDIATION_LEVEL_V2.put("W", "Workaround");
    REMEDIATION_LEVEL_V2.put("U", "Unavailable");

    REPORT_CONFIDENCE_V2.put("ND", "Not Defined");
    REPORT_CONFIDENCE_V2.put("UC", "Unknown");
    REPORT_CONFIDENCE_V2.put("UR", "Reasonable");
    REPORT_CONFIDENCE_V2.put("C", "Confirmed");
  }

  public static CvssVector fromVectorString(String vector) {
    Objects.requireNonNull(vector);
    var result = new CvssVector();
    var parts = vector.split("/");
    for (int i = 0; i < parts.length; i++) {
      var metrics = parts[i].split(":");
      if (vector.startsWith(V3_1) || vector.startsWith(V3_0)) {
        if (metrics.length == 2 && INDEX.containsKey(metrics[0])) {
          var item = INDEX.get(metrics[0]);
          var value = item.parameters().get(metrics[1]);
          item.setter().accept(value, result);
        }
      } else {
        // Parse CVSS 2.0
        if (metrics.length == 2 && INDEX_V2.containsKey(metrics[0])) {
          var item = INDEX_V2.get(metrics[0]);
          var value = item.parameters().get(metrics[1]);
          item.setter().accept(value, result);
        }
      }
    }

    return result.cvss(vector);
  }

  private CvssParser() {}
}
