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

package com.redhat.exhort.integration.backend;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Objects;

import org.apache.camel.Header;
import org.jboss.resteasy.reactive.common.util.MediaTypeHelper;

import com.redhat.exhort.integration.Constants;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response.Status;

@RegisterForReflection
public class BackendUtils {

  public BackendUtils() {
    this.clock = Clock.systemDefaultZone();
  }

  public BackendUtils(Clock clock) {
    this.clock = clock;
  }

  private Clock clock;

  public String getResponseMediaType(@Header(Constants.ACCEPT_HEADER) String acceptHeader) {
    if (acceptHeader == null || acceptHeader.isBlank()) {
      return Constants.DEFAULT_ACCEPT_MEDIA_TYPE;
    }
    var requested = MediaTypeHelper.parseHeader(acceptHeader);
    var match = MediaTypeHelper.getBestMatch(Constants.VALID_RESPONSE_MEDIA_TYPES, requested);
    if (match == null) {
      throw new ClientErrorException(
          "Unexpected Accept header "
              + acceptHeader
              + ". Supported content types are: "
              + Constants.VALID_RESPONSE_MEDIA_TYPES,
          Status.UNSUPPORTED_MEDIA_TYPE);
    }
    return match.toString();
  }

  public String generateRequestId(@Header(Constants.TRUST_DA_TOKEN_HEADER) String rhdaToken) {
    byte[] requestId;
    try {
      MessageDigest digestMaker = MessageDigest.getInstance("SHA-256");
      String tsOfNow;
      tsOfNow = LocalDateTime.now(this.clock).toString();
      var token = rhdaToken;
      if (Objects.isNull(rhdaToken) || rhdaToken.trim().equals("")) {
        token = Double.valueOf(Math.random()).toString();
      }
      byte[] inputForSha256 = new String(token + tsOfNow).getBytes(StandardCharsets.UTF_8);
      requestId = digestMaker.digest(inputForSha256);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    return bytesToHex(requestId);
  }

  private static String bytesToHex(byte[] hash) {
    StringBuilder hexString = new StringBuilder(2 * hash.length);
    for (int i = 0; i < hash.length; i++) {
      String hex = Integer.toHexString(0xff & hash[i]);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    return hexString.toString();
  }
}
