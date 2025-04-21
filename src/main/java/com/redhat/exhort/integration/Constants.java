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

package com.redhat.exhort.integration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.ws.rs.core.MediaType;

@RegisterForReflection
public final class Constants {

  private Constants() {}

  public static final String PROVIDER_NAME = "providerName";

  public static final String EXCLUDE_FROM_READINESS_CHECK = "exclusionFromReadiness";
  public static final String PROVIDERS_PARAM = "providers";

  public static final String HEALTH_CHECKS_LIST_HEADER_NAME = "healthChecksRoutesList";
  public static final String SBOM_TYPE_PARAM = "sbomType";

  public static final String ACCEPT_HEADER = "Accept";
  public static final String ACCEPT_ENCODING_HEADER = "Accept-Encoding";
  public static final String AUTHORIZATION_HEADER = "Authorization";
  public static final String SNYK_TOKEN_HEADER = "ex-snyk-token";
  public static final String SNYK_USER_AGENT_HEADER_FORMAT = "redhat-snyk-%s-%s";
  public static final String OSS_INDEX_USER_HEADER = "ex-oss-index-user";
  public static final String OSS_INDEX_TOKEN_HEADER = "ex-oss-index-token";
  public static final String TPA_TOKEN_HEADER = "ex-tpa-token";

  public static final String VERBOSE_MODE_HEADER = "verbose";

  public static final String RHDA_TOKEN_HEADER = "rhda-token";
  public static final String RHDA_SOURCE_HEADER = "rhda-source";
  public static final String RHDA_OPERATION_TYPE_HEADER = "rhda-operation-type";
  public static final String USER_AGENT_HEADER = "User-Agent";
  public static final String EXHORT_REQUEST_ID_HEADER = "ex-request-id";
  public static final MediaType MULTIPART_MIXED_TYPE = new MediaType("multipart", "mixed");
  public static final String MULTIPART_MIXED = MULTIPART_MIXED_TYPE.toString();
  public static final String SPDX_MEDIATYPE_JSON = "application/vnd.spdx+json";

  public static final String SNYK_PROVIDER = "snyk";
  public static final String OSS_INDEX_PROVIDER = "oss-index";
  public static final String TRUSTED_CONTENT_PROVIDER = "trusted-content";
  public static final String TPA_PROVIDER = "tpa";
  public static final String UNKNOWN_PROVIDER = "unknown";

  public static final String HTTP_UNAUTHENTICATED = "Unauthenticated";

  // PURL Types used in the application. See Snyk Supported PURL Types
  public static final String MAVEN_PURL_TYPE = "maven";
  public static final String NPM_PURL_TYPE = "npm";
  public static final String PYPI_PURL_TYPE = "pypi";
  public static final String GOLANG_PURL_TYPE = "golang";
  public static final String DEB_PURL_TYPE = "deb";
  public static final String NUGET_PURL_TYPE = "nuget";
  public static final String GEM_PURL_TYPE = "gem";
  public static final String COCOAPODS_PURL_TYPE = "cocoapods";
  public static final String RPM_PURL_TYPE = "rpm";
  public static final String OCI_PURL_TYPE = "oci";

  public static final String PKG_MANAGER_PROPERTY = "pkgManager";
  public static final String REQUEST_CONTENT_PROPERTY = "requestContent";
  public static final String REPORT_PROPERTY = "report";
  public static final String REPORTS_PROPERTY = "reports";
  public static final String PROVIDER_PRIVATE_DATA_PROPERTY = "providerPrivateData";
  public static final String RESPONSE_STATUS_PROPERTY = "responseStatus";
  public static final String DEPENDENCY_TREE_PROPERTY = "dependencyTree";
  public static final String API_VERSION_PROPERTY = "apiVersion";
  public static final String GZIP_RESPONSE_PROPERTY = "gzipResponse";
  public static final String SBOM_ID_PROPERTY = "sbomId";
  public static final String UNSCANNED_REFS_PROPERTY = "unscannedRefs";
  public static final String CACHED_RECOMMENDATIONS = "missedRecommendations";

  public static final String API_VERSION_V4 = "v4";
  public static final String API_VERSION_V3 = "v3";

  public static final String SNYK_DEP_GRAPH_API_PATH = "/test/dep-graph";
  public static final String SNYK_TOKEN_API_PATH = "/user/me";

  public static final String OSS_INDEX_AUTH_COMPONENT_API_PATH = "/authorized/component-report";
  public static final String OSS_INDEX_VERSION_PATH = "/version";

  public static final String TRUSTED_CONTENT_PATH = "/recommend";
  public static final String TPA_ANALYZE_PATH = "/vulnerability/analyze";
  public static final String TPA_HEALTH_PATH = "/health/live";
  public static final String TPA_TOKEN_PATH = "/vulnerability";

  public static final String DEFAULT_ACCEPT_MEDIA_TYPE = MediaType.APPLICATION_JSON;
  public static final boolean DEFAULT_VERBOSE_MODE = false;

  public static final String UNSCANNED_REASON_UNSUPPORTED_PACKAGE_TYPE = "unsupported-pkg-type";

  public static final String ANONYMOUS_ID_PROPERTY = "telemetry-anonymous-id";

  public static final String TELEMETRY_WRITE_KEY = "telemetry.write-key";

  public static final List<String> PROVIDERS =
      Collections.unmodifiableList(
          new ArrayList<>() {
            {
              add(SNYK_PROVIDER);
              add(OSS_INDEX_PROVIDER);
              add(TPA_PROVIDER);
            }
          });

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
