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

package io.github.guacsec.trustifyda.monitoring;

import java.util.Optional;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.github.guacsec.trustifyda.monitoring.impl.SentryMonitoringClient;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.sentry.Hub;
import io.sentry.SentryOptions;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
@RegisterForReflection
public class SentryMonitoringClientFactory {

  @ConfigProperty(name = "monitoring.sentry.dsn")
  Optional<String> dsn;

  @ConfigProperty(name = "monitoring.sentry.servername")
  Optional<String> serverName;

  @ConfigProperty(name = "monitoring.sentry.environment", defaultValue = "production")
  String environment;

  public MonitoringClient newInstance() {
    SentryOptions opt = new SentryOptions();
    opt.setDsn(dsn.get());
    opt.setEnvironment(environment);
    opt.setTag("server_name", serverName.get());
    return new SentryMonitoringClient(new Hub(opt));
  }
}
