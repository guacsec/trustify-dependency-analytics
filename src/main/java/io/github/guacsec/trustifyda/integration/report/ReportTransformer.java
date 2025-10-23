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

import java.util.Map;
import java.util.stream.Collectors;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.apache.camel.Header;
import org.apache.camel.attachment.AttachmentMessage;

import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.integration.Constants;
import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.activation.DataHandler;
import jakarta.ws.rs.core.MediaType;

@RegisterForReflection
public class ReportTransformer {

  public AnalysisReport filterVerboseResult(
      @Body AnalysisReport report, @Header(Constants.VERBOSE_MODE_HEADER) Boolean verbose) {
    if (Boolean.FALSE.equals(verbose)) {
      AnalysisReport filtered = new AnalysisReport().scanned(report.getScanned());
      report
          .getProviders()
          .entrySet()
          .forEach(
              e -> {
                ProviderReport providerReport =
                    new ProviderReport().status(e.getValue().getStatus());
                e.getValue()
                    .getSources()
                    .entrySet()
                    .forEach(
                        se -> {
                          providerReport.putSourcesItem(
                              se.getKey(), new Source().summary(se.getValue().getSummary()));
                        });
                filtered.putProvidersItem(e.getKey(), providerReport);
              });
      return filtered;
    }
    return report;
  }

  public Map<String, AnalysisReport> batchFilterVerboseResult(
      @Body Map<String, AnalysisReport> reports,
      @Header(Constants.VERBOSE_MODE_HEADER) Boolean verbose) {
    return reports.entrySet().stream()
        .collect(
            Collectors.toMap(Map.Entry::getKey, e -> filterVerboseResult(e.getValue(), verbose)));
  }

  public void attachHtmlReport(Exchange exchange) {
    exchange
        .getIn(AttachmentMessage.class)
        .addAttachment(
            "report.html",
            new DataHandler(exchange.getIn().getBody(String.class), MediaType.TEXT_HTML));
  }
}
