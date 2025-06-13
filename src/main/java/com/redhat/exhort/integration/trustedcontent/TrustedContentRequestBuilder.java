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

package com.redhat.exhort.integration.trustedcontent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.camel.Exchange;
import org.apache.camel.ExchangeProperty;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.cache.CacheService;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.trustedcontent.IndexedRecommendation;
import com.redhat.exhort.model.trustedcontent.TrustedContentCachedRequest;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@RegisterForReflection
public class TrustedContentRequestBuilder {

  private static final int BULK_SIZE = 128;

  @Inject ObjectMapper mapper;

  @Inject CacheService cacheService;

  public List<List<PackageRef>> split(Set<PackageRef> misses) {
    List<List<PackageRef>> bulks = new ArrayList<>();
    List<PackageRef> bulk = new ArrayList<>();
    for (var miss : misses) {
      if (bulk.size() == BULK_SIZE) {
        bulks.add(bulk);
        bulk = new ArrayList<>();
      }
      bulk.add(miss);
    }
    if (!bulk.isEmpty()) {
      bulks.add(bulk);
    }
    if (bulks.isEmpty()) {
      return null;
    }
    return bulks;
  }

  public String buildRequest(Set<PackageRef> misses) throws JsonProcessingException {

    var node = mapper.createArrayNode();
    misses.stream().map(PackageRef::toString).forEach(node::add);
    var obj = mapper.createObjectNode().set("purls", node);
    return mapper.writeValueAsString(obj);
  }

  public Set<PackageRef> filterCachedRecommendations(
      @ExchangeProperty(Constants.DEPENDENCY_TREE_PROPERTY) DependencyTree tree,
      Exchange exchange) {
    Set<PackageRef> miss = new HashSet<>();
    var allRefs = tree.getAll();
    var cached = cacheService.getRecommendations(allRefs);

    Map<PackageRef, IndexedRecommendation> cachedIdxRecommendations = new HashMap<>();
    allRefs.forEach(
        p -> {
          var cachedReq = cached.get(p);
          if (cachedReq == null) {
            miss.add(p);
          } else if (cachedReq.recommendation() != null) {
            cachedIdxRecommendations.put(p, cachedReq.recommendation());
          }
        });
    var req = new TrustedContentCachedRequest(cachedIdxRecommendations, miss);
    exchange.setProperty(Constants.CACHED_RECOMMENDATIONS, req);
    return req.miss();
  }
}
