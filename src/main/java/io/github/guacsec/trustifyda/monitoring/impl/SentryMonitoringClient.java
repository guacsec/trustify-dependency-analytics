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

package io.github.guacsec.trustifyda.monitoring.impl;

import java.util.Map;

import io.github.guacsec.trustifyda.config.exception.DetailedException;
import io.github.guacsec.trustifyda.monitoring.MonitoringClient;
import io.github.guacsec.trustifyda.monitoring.MonitoringContext;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.sentry.Hub;
import io.sentry.protocol.User;

@RegisterForReflection
public class SentryMonitoringClient implements MonitoringClient {

  private final Hub hub;

  public SentryMonitoringClient(Hub hub) {
    this.hub = hub;
  }

  @Override
  public void reportException(Throwable exception, MonitoringContext context) {
    if (!context.breadcrumbs().isEmpty()) {
      context.breadcrumbs().forEach(b -> hub.addBreadcrumb(b));
    }
    if (context.userId() != null) {
      var user = new User();
      user.setId(context.userId());
      hub.setUser(user);
    }
    addAdditionalData(hub, context.metadata(), context.tags());

    if (exception instanceof DetailedException) {
      DetailedException detailedException = (DetailedException) exception;
      String details = detailedException.getDetails();
      if (details != null) {
        hub.setExtra("Error details", details);
      }
    }
    hub.captureException(exception);
  }

  private void addAdditionalData(Hub hub, Map<String, String> metadata, Map<String, String> tags) {
    if (metadata != null) {
      metadata.entrySet().stream()
          .filter(e -> e.getValue() != null)
          .forEach(e -> hub.setExtra(e.getKey(), e.getValue()));
    }
    if (tags != null) {
      tags.entrySet().stream()
          .filter(e -> e.getValue() != null)
          .forEach(t -> hub.setTag(t.getKey(), t.getValue()));
    }
  }
}
