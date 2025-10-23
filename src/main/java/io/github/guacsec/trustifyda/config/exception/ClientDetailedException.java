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

package io.github.guacsec.trustifyda.config.exception;

import jakarta.ws.rs.core.Response;

public class ClientDetailedException extends DetailedException {

  public ClientDetailedException(String message) {
    super(message);
  }

  public ClientDetailedException(String message, String details) {
    super(message, details);
  }

  public ClientDetailedException(Throwable e) {
    super(e.getMessage(), null);
  }

  public ClientDetailedException(String message, Throwable e) {
    super(message, e.getMessage());
  }

  public int getStatus() {
    return Response.Status.BAD_REQUEST.getStatusCode();
  }
}
