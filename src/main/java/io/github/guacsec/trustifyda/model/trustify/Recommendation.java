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

package io.github.guacsec.trustifyda.model.trustify;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public record Recommendation(
    @JsonProperty("package") PackageRef packageName, List<Vulnerability> vulnerabilities) {

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    public PackageRef packageName;

    public List<Vulnerability> vulnerabilities;

    public Builder packageName(PackageRef packageName) {
      this.packageName = packageName;
      return this;
    }

    public Builder vulnerabilities(List<Vulnerability> vulnerabilities) {
      this.vulnerabilities = vulnerabilities;
      return this;
    }

    public Recommendation build() {
      return new Recommendation(packageName, vulnerabilities);
    }
  }
}
