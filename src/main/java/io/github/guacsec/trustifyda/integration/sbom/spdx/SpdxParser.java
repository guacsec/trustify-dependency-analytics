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

package io.github.guacsec.trustifyda.integration.sbom.spdx;

import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.config.exception.SpdxValidationException;
import io.github.guacsec.trustifyda.integration.sbom.SbomParser;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.DirectDependency;

public class SpdxParser extends SbomParser {

  @Override
  public DependencyTree buildTree(InputStream input) {
    var wrapper = new SpdxWrapper(input);
    var deps = buildDeps(wrapper);
    return new DependencyTree(deps, null, null);
  }

  private Map<PackageRef, DirectDependency> buildDeps(SpdxWrapper wrapper) {
    var startFrom = wrapper.getStartFromPackages();
    if (startFrom == null) {
      throw new SpdxValidationException("No valid root packages found in SPDX SBOM");
    }
    Map<PackageRef, DirectDependency> tree = new HashMap<>();
    Set<PackageRef> visited = new HashSet<>();
    var relationships = wrapper.getRelationships();

    for (PackageRef ref : startFrom) {
      Set<PackageRef> deps = new HashSet<>();
      retrieveTransitive(ref, deps, relationships, visited);
      tree.put(ref, new DirectDependency(ref, deps));
      visited.add(ref);
    }

    // Orphan packages are added to the tree as a direct dependency
    if (visited.size() < relationships.size()) {
      for (var rel : relationships.entrySet()) {
        if (!visited.contains(rel.getKey())) {
          Set<PackageRef> deps = new HashSet<>();
          retrieveTransitive(rel.getKey(), deps, relationships, visited);
          tree.put(rel.getKey(), new DirectDependency(rel.getKey(), deps));
        }
      }
    }

    return tree;
  }

  private void retrieveTransitive(
      PackageRef ref,
      Set<PackageRef> deps,
      Map<PackageRef, Set<PackageRef>> relationships,
      Set<PackageRef> visited) {
    var refDeps = relationships.get(ref);
    if (refDeps == null) {
      return;
    }
    for (var dep : refDeps) {
      if (!deps.contains(dep)) {
        deps.add(dep);
        retrieveTransitive(dep, deps, relationships, visited);
        visited.add(dep);
      }
    }
  }
}
