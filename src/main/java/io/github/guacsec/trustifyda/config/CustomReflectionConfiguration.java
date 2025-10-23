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

package io.github.guacsec.trustifyda.config;

import org.apache.camel.http.base.HttpOperationFailedException;
import org.jboss.resteasy.reactive.common.jaxrs.ResponseImpl;
import org.spdx.storage.listedlicense.LicenseJsonTOC;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

@RegisterForReflection(
    targets = {
      HttpOperationFailedException.class,
      WebApplicationException.class,
      ClientErrorException.class,
      Response.class,
      ResponseImpl.class,
      LicenseJsonTOC.class
    })
public class CustomReflectionConfiguration {}
