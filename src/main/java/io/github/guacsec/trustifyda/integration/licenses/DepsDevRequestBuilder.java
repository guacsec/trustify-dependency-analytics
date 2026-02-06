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

package io.github.guacsec.trustifyda.integration.licenses;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.LicensesRequest;
import io.github.guacsec.trustifyda.config.ObjectMapperProducer;
import io.github.guacsec.trustifyda.model.DependencyTree;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class DepsDevRequestBuilder {

  private static final ObjectMapper MAPPER = ObjectMapperProducer.newInstance();

  private static final int BATCH_SIZE = 500;

  public boolean isEmpty(List<PackageRef> purls) {
    return purls == null || purls.isEmpty();
  }

  /**
   * Builds the Deps.dev request JSON from a list of purls (used for full request or each batch).
   */
  public JsonNode toRequest(List<PackageRef> purls) {
    var depsDevReq = MAPPER.createObjectNode();
    var requests = MAPPER.createArrayNode();
    for (var p : purls) {
      requests.add(MAPPER.createObjectNode().put("purl", p.purl().getCoordinates()));
    }
    depsDevReq.set("requests", requests);
    return depsDevReq;
  }

  public List<PackageRef> fromEndpoint(LicensesRequest request) {
    if (request == null || request.getPurls() == null) {
      return Collections.emptyList();
    }
    return request.getPurls();
  }

  public List<PackageRef> fromSbom(DependencyTree tree) {
    var purls = tree.getAll();
    return new ArrayList<PackageRef>(purls);
  }

  /**
   * Splits the licenses request into chunks of at most {@value #BATCH_SIZE} purls. Each chunk is
   * then turned into a request via {@link #toRequest(List)} in the route.
   */
  public List<List<PackageRef>> splitIntoBatches(List<PackageRef> purls) {
    if (purls == null || purls.isEmpty()) {
      return Collections.emptyList();
    }
    List<List<PackageRef>> batches = new ArrayList<>();
    List<PackageRef> batch = new ArrayList<>();
    for (var p : purls) {
      if (batch.size() == BATCH_SIZE) {
        batches.add(batch);
        batch = new ArrayList<>();
      }
      batch.add(p);
    }
    if (!batch.isEmpty()) {
      batches.add(batch);
    }
    return batches;
  }
}
