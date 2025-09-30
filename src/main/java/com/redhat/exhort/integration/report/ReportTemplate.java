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

package com.redhat.exhort.integration.report;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangeProperty;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.trustedcontent.ubi.UBIRecommendation;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@RegisterForReflection
@ApplicationScoped
public class ReportTemplate {

  @ConfigProperty(name = "report.nvd.issue.regex")
  String nvdIssuePathRegex;

  @ConfigProperty(name = "report.cve.issue.regex")
  String cveIssuePathRegex;

  @Inject UBIRecommendation ubiRecommendation;

  @ConfigProperty(name = Constants.TELEMETRY_WRITE_KEY)
  Optional<String> writeKey;

  @ConfigProperty(name = "telemetry.disabled", defaultValue = "false")
  Boolean disabled;

  @Inject ObjectMapper mapper;

  public Map<String, Object> setVariables(
      Exchange exchange,
      @Body Object report,
      @ExchangeProperty(Constants.ANONYMOUS_ID_PROPERTY) String anonymousId,
      @ExchangeProperty(Constants.RHDA_TOKEN_HEADER) String userId,
      @ExchangeProperty(Constants.RHDA_SOURCE_HEADER) String rhdaSource,
      @ExchangeProperty(Constants.PROVIDER_PRIVATE_DATA_PROPERTY) List<String> providerPrivateData)
      throws JsonMappingException, JsonProcessingException, IOException {

    Map<String, Object> params = new HashMap<>();
    params.put("report", report);
    params.put("nvdIssueTemplate", nvdIssuePathRegex);
    params.put("providerPrivateData", providerPrivateData);
    params.put("cveIssueTemplate", cveIssuePathRegex);
    params.put("imageMapping", getImageMapping());
    params.put("rhdaSource", rhdaSource);
    if (!disabled && writeKey.isPresent()) {
      params.put("userId", userId);
      params.put("anonymousId", anonymousId);
      params.put("writeKey", writeKey.get());
    }

    var appData = mapper.writeValueAsString(params);
    params.put("appData", sanitize(appData));

    return params;
  }

  private String sanitize(String report) {
    String sanitizedReport = report.replaceAll("<script>", "\\\\<script\\\\>");
    sanitizedReport = sanitizedReport.replaceAll("%40", "");
    return sanitizedReport;
  }

  private String getImageMapping() throws JsonProcessingException {
    List<Map<String, String>> urlMapping =
        ubiRecommendation.purl().keySet().stream()
            .map(
                ubi -> {
                  Map<String, String> urls = new HashMap<>(2);
                  urls.put("purl", ubiRecommendation.purl().get(ubi));
                  urls.put("catalogUrl", ubiRecommendation.catalogurl().get(ubi));
                  return urls;
                })
            .toList();

    ObjectWriter objectWriter = new ObjectMapper().writer();
    return objectWriter.writeValueAsString(urlMapping);
  }

  @RegisterForReflection
  public static record IssueLinkFormatter(String issuePathRegex) {

    public String format(String id) {
      return String.format(issuePathRegex, id, id);
    }
  }
}
