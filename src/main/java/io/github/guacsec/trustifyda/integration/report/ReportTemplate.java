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

package io.github.guacsec.trustifyda.integration.report;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangeProperty;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.trustedcontent.ubi.UBIRecommendation;
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
      @ExchangeProperty(Constants.TRUST_DA_TOKEN_HEADER) String userId,
      @ExchangeProperty(Constants.TRUST_DA_SOURCE_HEADER) String rhdaSource)
      throws JsonMappingException, JsonProcessingException, IOException {

    Map<String, Object> params = new HashMap<>();
    params.put("report", report);
    params.put("nvdIssueTemplate", nvdIssuePathRegex);
    params.put("cveIssueTemplate", cveIssuePathRegex);
    params.put("imageMapping", getImageMapping());
    params.put("rhdaSource", rhdaSource);
    getBrandingConfig()
        .ifPresent(config -> params.put("brandingConfig", getBrandingConfigMap(config)));
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

  private Optional<BrandingConfig> getBrandingConfig() {
    try {
      Config config = ConfigProvider.getConfig();
      return config
          .getOptionalValue("branding.display-name", String.class)
          .filter(displayName -> !displayName.isEmpty())
          .map(
              displayName ->
                  new BrandingConfigImpl(
                      displayName,
                      config.getOptionalValue("branding.explore-url", String.class).orElse(""),
                      config.getOptionalValue("branding.explore-title", String.class).orElse(""),
                      config
                          .getOptionalValue("branding.explore-description", String.class)
                          .orElse(""),
                      config
                          .getOptionalValue("branding.image-recommendation", String.class)
                          .orElse(""),
                      config
                          .getOptionalValue("branding.image-remediation-link", String.class)
                          .orElse("")));
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  private Map<String, String> getBrandingConfigMap(BrandingConfig config) {
    Map<String, String> branding = new HashMap<>();
    branding.put("displayName", config.displayName());
    branding.put("exploreUrl", config.exploreUrl());
    branding.put("exploreTitle", config.exploreTitle());
    branding.put("exploreDescription", config.exploreDescription());
    branding.put("imageRecommendation", config.imageRecommendation());
    branding.put("imageRemediationLink", config.imageRemediationLink());
    return branding;
  }

  @RegisterForReflection
  private static class BrandingConfigImpl implements BrandingConfig {
    private final String displayName;
    private final String exploreUrl;
    private final String exploreTitle;
    private final String exploreDescription;
    private final String imageRecommendation;
    private final String imageRemediationLink;

    public BrandingConfigImpl(
        String displayName,
        String exploreUrl,
        String exploreTitle,
        String exploreDescription,
        String imageRecommendation,
        String imageRemediationLink) {
      this.displayName = displayName;
      this.exploreUrl = exploreUrl;
      this.exploreTitle = exploreTitle;
      this.exploreDescription = exploreDescription;
      this.imageRecommendation = imageRecommendation;
      this.imageRemediationLink = imageRemediationLink;
    }

    @Override
    public String displayName() {
      return displayName;
    }

    @Override
    public String exploreUrl() {
      return exploreUrl;
    }

    @Override
    public String exploreTitle() {
      return exploreTitle;
    }

    @Override
    public String exploreDescription() {
      return exploreDescription;
    }

    @Override
    public String imageRecommendation() {
      return imageRecommendation;
    }

    @Override
    public String imageRemediationLink() {
      return imageRemediationLink;
    }
  }

  @RegisterForReflection
  public static record IssueLinkFormatter(String issuePathRegex) {

    public String format(String id) {
      return String.format(issuePathRegex, id, id);
    }
  }
}
