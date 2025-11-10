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

package io.github.guacsec.trustifyda.integration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.ws.rs.core.MediaType;

@RegisterForReflection
public final class Constants {

  private Constants() {}

  public static final String PROVIDER_NAME_PROPERTY = "providerName";

  public static final String EXCLUDE_FROM_READINESS_CHECK = "exclusionFromReadiness";
  public static final String PROVIDERS_PARAM = "providers";
  public static final String RECOMMEND_PARAM = "recommend";

  public static final String HEALTH_CHECKS_LIST_HEADER_NAME = "healthChecksRoutesList";
  public static final String SBOM_TYPE_PARAM = "sbomType";

  public static final String ACCEPT_HEADER = "Accept";
  public static final String ACCEPT_ENCODING_HEADER = "Accept-Encoding";
  public static final String AUTHORIZATION_HEADER = "Authorization";
  public static final String TRUSTIFY_TOKEN_HEADER = "ex-trustify-token";

  public static final String VERBOSE_MODE_HEADER = "verbose";

  public static final String TRUST_DA_TOKEN_HEADER = "trust-da-token";
  public static final String TRUST_DA_SOURCE_HEADER = "trust-da-source";
  public static final String TRUST_DA_OPERATION_TYPE_HEADER = "trust-da-operation-type";
  public static final String TRUST_DA_PKG_MANAGER_HEADER = "trust-da-pkg-manager";
  public static final String USER_AGENT_HEADER = "User-Agent";
  public static final String EXHORT_REQUEST_ID_HEADER = "ex-request-id";
  public static final MediaType MULTIPART_MIXED_TYPE = new MediaType("multipart", "mixed");
  public static final String MULTIPART_MIXED = MULTIPART_MIXED_TYPE.toString();
  public static final String SPDX_MEDIATYPE_JSON = "application/vnd.spdx+json";
  public static final String CYCLONEDX_MEDIATYPE_JSON = "application/vnd.cyclonedx+json";

  public static final String OSV_PROVIDER = "osv";

  public static final String HTTP_UNAUTHENTICATED = "Unauthenticated";

  public static final String REQUEST_CONTENT_PROPERTY = "requestContent";
  public static final String REPORT_PROPERTY = "report";
  public static final String REPORTS_PROPERTY = "reports";
  public static final String RESPONSE_STATUS_PROPERTY = "responseStatus";
  public static final String DEPENDENCY_TREE_PROPERTY = "dependencyTree";
  public static final String API_VERSION_PROPERTY = "apiVersion";
  public static final String GZIP_RESPONSE_PROPERTY = "gzipResponse";
  public static final String SBOM_ID_PROPERTY = "sbomId";
  public static final String PROVIDER_CONFIG_PROPERTY = "providerConfig";
  public static final String PROVIDERS_PROPERTY = "providers";

  public static final String OSV_NVD_PURLS_PATH = "/purls";
  public static final String OSV_NVD_HEALTH_PATH = "/q/health";

  public static final String TRUSTIFY_RECOMMEND_PATH = "/api/v2/purl/recommend";
  public static final String TRUSTIFY_ANALYZE_PATH = "/api/v2/vulnerability/analyze";
  public static final String TRUSTIFY_HEALTH_PATH = "/.well-known/trustify";

  public static final String DEFAULT_ACCEPT_MEDIA_TYPE = MediaType.APPLICATION_JSON;

  public static final String ANONYMOUS_ID_PROPERTY = "telemetry-anonymous-id";

  public static final String TELEMETRY_WRITE_KEY = "telemetry.write-key";

  public static final List<MediaType> VALID_RESPONSE_MEDIA_TYPES =
      Collections.unmodifiableList(
          new ArrayList<>() {
            {
              add(MediaType.APPLICATION_JSON_TYPE);
              add(MediaType.TEXT_HTML_TYPE);
              add(MULTIPART_MIXED_TYPE);
            }
          });
  public static final String AUTH_PROVIDER_REQ_PROPERTY_PREFIX = "anonymous_";
}
