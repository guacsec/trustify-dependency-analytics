/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.providers.ossindex;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.camel.Body;
import org.apache.camel.Header;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.config.ObjectMapperProducer;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.model.DependencyTree;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class OssIndexRequestBuilder {

  private static final int BULK_SIZE = 128;

  private final ObjectMapper mapper = ObjectMapperProducer.newInstance();

  public List<List<PackageRef>> split(DependencyTree tree) {
    List<List<PackageRef>> bulks = new ArrayList<>();
    tree.getAll()
        .forEach(
            d -> {
              if (bulks.isEmpty()) {
                bulks.add(new ArrayList<>());
              }
              var bulk = bulks.get(bulks.size() - 1);
              if (bulk.size() == BULK_SIZE) {
                bulk = new ArrayList<>();
                bulks.add(bulk);
              }
              bulk.add(d);
            });
    return bulks;
  }

  public boolean isEmpty(@Body Collection<List<PackageRef>> body) {
    return body == null || body.isEmpty();
  }

  public boolean missingAuthHeaders(
      @Header(Constants.OSS_INDEX_USER_HEADER) String user,
      @Header(Constants.OSS_INDEX_TOKEN_HEADER) String token) {
    return user == null || token == null;
  }

  public String buildRequest(List<PackageRef> packages) throws JsonProcessingException {
    var coordinates = mapper.createArrayNode();
    // oss-index don't allow qualifiers
    packages.stream()
        .map(PackageRef::purl)
        .map(PackageURL::getCoordinates)
        .forEach(coordinates::add);
    var root = mapper.createObjectNode().set("coordinates", coordinates);
    return mapper.writeValueAsString(root);
  }
}
