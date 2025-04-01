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

package com.redhat.exhort.integration.providers.tpa;

import java.util.Optional;

import org.apache.camel.Exchange;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.exhort.config.ObjectMapperProducer;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.model.DependencyTree;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
@RegisterForReflection
public class TpaRequestBuilder {

  @ConfigProperty(name = "api.tpa.token")
  Optional<String> defaultToken;

  private ObjectMapper mapper = ObjectMapperProducer.newInstance();

  public String buildRequest(DependencyTree tree) throws JsonProcessingException {
    var request = mapper.createObjectNode();
    var purls = mapper.createArrayNode();
    tree.getAll().forEach(dep -> purls.add(dep.ref()));
    request.set("purls", purls);
    return mapper.writeValueAsString(request);
  }

  public void addAuthentication(Exchange exchange) {
    var message = exchange.getMessage();
    var userToken = message.getHeader(Constants.TPA_TOKEN_HEADER, String.class);
    String token = null;
    if (userToken != null) {
      token = userToken;
    } else if (defaultToken.isPresent()) {
      token = defaultToken.get();
    }
    if (token != null) {
      message.setHeader("Authorization", "Bearer " + token);
    }
  }

  public boolean isEmpty(DependencyTree tree) {
    return tree.dependencies().isEmpty();
  }
}
