/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.providers.trustify;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.exhort.config.ObjectMapperProducer;
import com.redhat.exhort.model.DependencyTree;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
@RegisterForReflection
public class TrustifyRequestBuilder {

  private static final int BULK_SIZE = 128;

  public static final String TRUSTIFY_CLIENT_TENANT = "trustify";

  private final ObjectMapper mapper = ObjectMapperProducer.newInstance();

  public String buildRequest(List<String> refs) throws JsonProcessingException {
    var request = mapper.createObjectNode();
    var purls = mapper.createArrayNode();
    refs.forEach(dep -> purls.add(dep));
    request.set("purls", purls);
    return mapper.writeValueAsString(request);
  }

  public List<List<String>> split(DependencyTree tree) {
    List<List<String>> bulks = new ArrayList<>();
    List<String> bulk = new ArrayList<>();
    for (var pkg : tree.getAll()) {
      if (bulk.size() == BULK_SIZE) {
        bulks.add(bulk);
        bulk = new ArrayList<>();
      }
      bulk.add(pkg.ref());
    }
    if (!bulk.isEmpty()) {
      bulks.add(bulk);
    }
    return bulks;
  }

  public boolean isEmpty(DependencyTree tree) {
    return tree.dependencies().isEmpty();
  }
}
