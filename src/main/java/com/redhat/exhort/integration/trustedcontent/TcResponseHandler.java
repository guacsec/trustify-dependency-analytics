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

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangeProperty;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.ProviderStatus;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.ProviderResponseHandler;
import com.redhat.exhort.integration.trustedcontent.ubi.UBIRecommendation;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.ProviderResponse;
import com.redhat.exhort.model.trustedcontent.IndexedRecommendation;
import com.redhat.exhort.model.trustedcontent.Recommendations;
import com.redhat.exhort.model.trustedcontent.TcRecommendation;
import com.redhat.exhort.model.trustedcontent.TrustedContentResponse;
import com.redhat.exhort.model.trustedcontent.Vulnerability;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response.Status;

@ApplicationScoped
@RegisterForReflection
public class TcResponseHandler extends ProviderResponseHandler {

  // Other values are Affected and UnderInvestigation
  // see https://www.cisa.gov/sites/default/files/2023-01/VEX_Status_Justification_Jun22.pdf
  private static final List<String> FIXED_STATUSES = List.of("NotAffected", "Fixed");

  private static final String OCI_PURL_TYPE = "oci";

  @Inject ObjectMapper mapper;

  @Inject UBIRecommendation ubiRecommendation;

  public TrustedContentResponse mergeSplitRecommendations(
      TrustedContentResponse oldResponse, TrustedContentResponse newResponse) {
    if (oldResponse == null) {
      return newResponse;
    }
    if (!oldResponse.status().getOk()) {
      return oldResponse;
    }
    oldResponse.recommendations().putAll(newResponse.recommendations());
    return oldResponse;
  }

  public TrustedContentResponse processRecommendations(
      Exchange exchange,
      @Body byte[] tcResponse,
      @ExchangeProperty(Constants.SBOM_ID_PROPERTY) String sbomId)
      throws IOException {
    var recommendations = mapper.readValue(tcResponse, Recommendations.class);
    var mergedRecommendations = mergeRecommendations(recommendations);
    mergedRecommendations.putAll(getUBIRecommendation(sbomId));

    return new TrustedContentResponse(
        mergedRecommendations,
        new ProviderStatus()
            .name(getProviderName(exchange))
            .code(Status.OK.getStatusCode())
            .message(Status.OK.getReasonPhrase())
            .ok(Boolean.TRUE));
  }

  private Map<PackageRef, IndexedRecommendation> mergeRecommendations(
      Recommendations recommendations) {
    Map<PackageRef, IndexedRecommendation> result = new HashMap<>();
    if (recommendations == null) {
      return result;
    }
    recommendations.getMatchings().entrySet().stream()
        .forEach(
            e -> result.put(new PackageRef(e.getKey()), aggregateRecommendations(e.getValue())));
    return result;
  }

  private IndexedRecommendation aggregateRecommendations(List<TcRecommendation> recommendations) {
    PackageRef pkgRef = getHighestRemediationRecommendation(recommendations);
    return new IndexedRecommendation(
        pkgRef,
        recommendations.stream()
            .map(TcRecommendation::vulnerabilities)
            .flatMap(List::stream)
            .collect(Collectors.toMap(v -> v.getId().toUpperCase(), v -> v, this::filterFixed)));
  }

  private PackageRef getHighestRemediationRecommendation(List<TcRecommendation> tcRecommendations) {
    return tcRecommendations.stream()
        .sorted(
            (rec1, rec2) ->
                Arrays.compare(
                    rec2.packageName().toString().toCharArray(),
                    rec1.packageName().toString().toCharArray()))
        .map(recommendedPackage -> recommendedPackage.packageName())
        .findFirst()
        .get();
  }

  private Map<PackageRef, IndexedRecommendation> getUBIRecommendation(String sbomId) {
    if (sbomId == null) {
      return Collections.emptyMap();
    }

    var pkgRef = new PackageRef(sbomId);
    if (!OCI_PURL_TYPE.equals(pkgRef.purl().getType())) {
      return Collections.emptyMap();
    }

    var recommendedUBIPurl = ubiRecommendation.mapping().get(pkgRef.name());
    if (recommendedUBIPurl != null) {
      var recommendation = new IndexedRecommendation(new PackageRef(recommendedUBIPurl), null);
      return Collections.singletonMap(pkgRef, recommendation);
    }
    return Collections.emptyMap();
  }

  @Override
  protected String getProviderName(Exchange exchange) {
    return Constants.TRUSTED_CONTENT_PROVIDER;
  }

  @Override
  public void processResponseError(Exchange exchange) {
    super.processResponseError(exchange);
    var response = exchange.getIn().getBody(ProviderResponse.class);
    exchange.getIn().setBody(new TrustedContentResponse(null, response.status()));
  }

  @Override
  public ProviderResponse responseToIssues(byte[] response, DependencyTree tree)
      throws IOException {
    throw new UnsupportedOperationException("Not yet implemented");
  }

  private Vulnerability filterFixed(Vulnerability a, Vulnerability b) {
    if (a.getStatus() != null && !FIXED_STATUSES.contains(a.getStatus())) {
      return a;
    }
    return b;
  }
}
