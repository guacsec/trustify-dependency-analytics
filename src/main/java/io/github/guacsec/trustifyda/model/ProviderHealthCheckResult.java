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

public record ProviderHealthCheckResult(
    String name, Boolean disabled, Boolean ok, Integer code, String message) {

  public static ProviderHealthCheckResult disabled(String name) {
    return new ProviderHealthCheckResult(name, true, true, null, null);
  }

  public static ProviderHealthCheckResult success(String name) {
    return new ProviderHealthCheckResult(name, false, true, null, null);
  }

  public static ProviderHealthCheckResult error(String name, Integer code, String message) {
    return new ProviderHealthCheckResult(name, false, false, code, message);
  }
}
