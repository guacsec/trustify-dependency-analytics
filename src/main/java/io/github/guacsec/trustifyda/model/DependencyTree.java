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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public record DependencyTree(Map<PackageRef, DirectDependency> dependencies) {

  public static final PackageRef getDefaultRoot(String type) {
    return PackageRef.builder()
        .pkgManager(type)
        .namespace("com.redhat.exhort")
        .name("default-app")
        .version("0.0.1")
        .build();
  }

  public DependencyTree {
    if (dependencies != null) {
      dependencies = Collections.unmodifiableMap(dependencies);
    } else {
      dependencies = Collections.emptyMap();
    }
  }

  public int directCount() {
    return dependencies.size();
  }

  public int transitiveCount() {
    return Long.valueOf(
            dependencies.values().stream()
                .map(d -> d.transitive())
                .flatMap(Collection::stream)
                .distinct()
                .count())
        .intValue();
  }

  public int count() {
    return directCount() + transitiveCount();
  }

  public Set<PackageRef> getAll() {
    var result = new HashSet<>(dependencies.keySet());
    dependencies
        .values()
        .forEach(
            d -> {
              if (d.transitive() != null && !d.transitive().isEmpty()) {
                result.addAll(d.transitive());
              }
            });
    return result.stream().filter(Objects::nonNull).collect(Collectors.toSet());
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    public Map<PackageRef, DirectDependency> dependencies;

    public Builder dependencies(Map<PackageRef, DirectDependency> dependencies) {
      this.dependencies = dependencies;
      return this;
    }

    public DependencyTree build() {
      return new DependencyTree(dependencies);
    }
  }
}
