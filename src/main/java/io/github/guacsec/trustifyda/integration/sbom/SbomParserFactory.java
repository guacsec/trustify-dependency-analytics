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

package io.github.guacsec.trustifyda.integration.sbom;

import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.sbom.cyclonedx.CycloneDxParser;
import io.github.guacsec.trustifyda.integration.sbom.spdx.SpdxParser;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;

public class SbomParserFactory {

  public static final SbomParser newInstance(String mediaType) {
    return switch (mediaType) {
      case Constants.CYCLONEDX_MEDIATYPE_JSON -> new CycloneDxParser();
      case Constants.SPDX_MEDIATYPE_JSON -> new SpdxParser();
      default -> throw new ClientErrorException(
          "Unsupported Content-Type header: " + mediaType, Response.Status.UNSUPPORTED_MEDIA_TYPE);
    };
  }
}
