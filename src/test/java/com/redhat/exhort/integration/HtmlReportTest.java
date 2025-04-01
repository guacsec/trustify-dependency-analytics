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

import static io.restassured.RestAssured.given;
import static org.apache.camel.Exchange.CONTENT_TYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.List;

import org.cyclonedx.CycloneDxMediaType;
import org.hamcrest.text.MatchesPattern;
import org.htmlunit.BrowserVersion;
import org.htmlunit.WebClient;
import org.htmlunit.html.DomElement;
import org.htmlunit.html.DomNodeList;
import org.htmlunit.html.HtmlAnchor;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlHeading2;
import org.htmlunit.html.HtmlHeading4;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlTable;
import org.htmlunit.html.HtmlTableBody;
import org.htmlunit.html.HtmlTableDataCell;
import org.htmlunit.html.HtmlTableRow;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

import jakarta.ws.rs.core.MediaType;

@QuarkusTest
public class HtmlReportTest extends AbstractAnalysisTest {

  private static final String CYCLONEDX = "cyclonedx";

  /**
   * The generated HTML only has 1 vulnerability tab for Snyk. The quarkus-hibernate-orm has a
   * private vulnerability that should be hidden and display the "Sign up" link to the user.
   *
   * <p>In order to expand the transitive table, it is required to click on the button contained in
   * the <td>
   */
  @Test
  public void testHtmlWithoutToken() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .when()
            .post("/api/v4/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.TEXT_HTML)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .asString();

    var webClient = initWebClient();
    HtmlPage page = extractPage(webClient, body);
    // Select the Snyk Source
    HtmlButton snykSourceBtn = page.getFirstByXPath("//button[@aria-label='snyk source']");
    assertNotNull(snykSourceBtn);

    page = click(webClient, snykSourceBtn);

    DomNodeList<DomElement> tables = page.getElementsByTagName("table");
    assertEquals(4, tables.size());
    DomElement snykTable = tables.get(3);
    HtmlTableBody tbody = getTableBodyForDependency("io.quarkus:quarkus-hibernate-orm", snykTable);
    assertNotNull(tbody);
    page = expandTransitiveTableDataCell(webClient, tbody);
    snykTable =
        page.getFirstByXPath("//table[contains(@aria-label, 'snyk transitive vulnerabilities')]");
    List<HtmlTableBody> tbodies = snykTable.getByXPath(".//tbody");
    HtmlTableBody privateIssueTbody =
        tbodies.stream()
            .filter(
                issuesTbody -> {
                  List<HtmlAnchor> tds = issuesTbody.getByXPath("./tr/td");
                  return tds.size() == 4;
                })
            .findFirst()
            .get();
    assertNotNull(privateIssueTbody);
    HtmlTableDataCell td = privateIssueTbody.getFirstByXPath("./tr/td");
    assertEquals(
        "Sign up for a Snyk account to learn about the vulnerabilities found",
        td.asNormalizedText());

    // Select the Oss-Index Source
    HtmlButton ossIndexSourceBtn = page.getFirstByXPath("//button[@aria-label='oss-index source']");
    assertNotNull(ossIndexSourceBtn);
    page = click(webClient, ossIndexSourceBtn);

    List<HtmlHeading2> headings = page.getByXPath("//div[@class='pf-v5-c-empty-state__title']/h2");
    assertEquals("Set up oss-index", headings.get(0).getTextContent());

    verifySnykRequest(null);
  }

  /**
   * This report contains both oss-index and snyk reports. So in order to show the Snyk report, we
   * need to click on the tab. Then the quarkus-hibernate-orm having the unique vulnerability should
   * appear without limitations.
   *
   * @throws IOException
   */
  @Test
  public void testHtmlWithToken() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.SNYK_TOKEN_HEADER, OK_TOKEN)
            .header(Constants.OSS_INDEX_USER_HEADER, OK_USER)
            .header(Constants.OSS_INDEX_TOKEN_HEADER, OK_TOKEN)
            .header(Constants.TPA_TOKEN_HEADER, OK_TOKEN)
            .when()
            .post("/api/v4/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.TEXT_HTML)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .asString();

    var webClient = initWebClient();
    HtmlPage page = extractPage(webClient, body);
    // Select the Snyk Source
    HtmlButton snykSourceBtn = page.getFirstByXPath("//button[@aria-label='snyk source']");
    assertNotNull(snykSourceBtn);
    page = click(webClient, snykSourceBtn);

    DomNodeList<DomElement> tables = page.getElementsByTagName("table");
    assertEquals(5, tables.size());

    HtmlTableBody tbody =
        getTableBodyForDependency("io.quarkus:quarkus-hibernate-orm", tables.get(2));
    assertNotNull(tbody);
    page = expandTransitiveTableDataCell(webClient, tbody);
    tables = page.getElementsByTagName("table");
    tbody = getTableBodyForDependency("io.quarkus:quarkus-hibernate-orm", tables.get(1));

    // TODO: figure out why the Snyk unique vulnerability is not being rendered in headless mode

    // HtmlTable issuesTable = getIssuesTable(tbody);
    // List<HtmlTableBody> tbodies = issuesTable.getByXPath(".//table//tbody");
    // HtmlTableBody privateIssueTbody = tbodies.stream().filter(issuesTbody -> {
    //   List<HtmlTableDataCell> tds = issuesTbody.getByXPath("./tr/td");
    //   return tds.get(0).asNormalizedText().startsWith("SNYK");

    // }).findFirst().get();
    // assertNotNull(privateIssueTbody);

    verifySnykRequest(OK_TOKEN);
    verifyOssRequest(OK_USER, OK_TOKEN);
    verifyTpaRequest(OK_TOKEN);
  }

  @Test
  public void testHtmlUnauthorized() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.SNYK_TOKEN_HEADER, INVALID_TOKEN)
            .when()
            .post("/api/v4/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.TEXT_HTML)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .asString();

    var webClient = initWebClient();
    HtmlPage page = extractPage(webClient, body);
    HtmlHeading4 heading = page.getFirstByXPath("//div[@class='pf-v5-c-alert pf-m-warning']/h4");
    assertEquals(
        "Warning alert:Snyk: Unauthorized: Verify the provided credentials are valid.",
        heading.getTextContent());

    // Select the Snyk Source
    HtmlButton snykSourceBtn = page.getFirstByXPath("//button[@aria-label='snyk source']");
    assertNotNull(snykSourceBtn);
    page = click(webClient, snykSourceBtn);
    final String pageAsText = page.asNormalizedText();
    assertTrue(pageAsText.contains("No results found"));

    verifySnykRequest(INVALID_TOKEN);
    verifyNoInteractionsWithOSS();
  }

  @Test
  public void testHtmlForbidden() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.SNYK_TOKEN_HEADER, UNAUTH_TOKEN)
            .when()
            .post("/api/v4/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.TEXT_HTML)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .asString();
    var webClient = initWebClient();
    HtmlPage page = extractPage(webClient, body);
    HtmlHeading4 heading = page.getFirstByXPath("//div[@class='pf-v5-c-alert pf-m-warning']/h4");
    assertEquals(
        "Warning alert:Snyk: Forbidden: The provided credentials don't have the required"
            + " permissions.",
        heading.getTextContent());

    // Select the Snyk Source
    HtmlButton snykSourceBtn = page.getFirstByXPath("//button[@aria-label='snyk source']");
    assertNotNull(snykSourceBtn);
    page = click(webClient, snykSourceBtn);
    final String pageAsText = page.asNormalizedText();
    assertTrue(pageAsText.contains("No results found"));

    verifySnykRequest(UNAUTH_TOKEN);
    verifyNoInteractionsWithOSS();
  }

  @Test
  public void testHtmlError() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.SNYK_TOKEN_HEADER, ERROR_TOKEN)
            .when()
            .post("/api/v4/analysis")
            .then()
            .assertThat()
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .statusCode(200)
            .contentType(MediaType.TEXT_HTML)
            .extract()
            .body()
            .asString();

    var webClient = initWebClient();
    HtmlPage page = extractPage(webClient, body);
    List<HtmlHeading4> headings = page.getByXPath("//div[@class='pf-v5-c-alert pf-m-danger']/h4");
    boolean foundHeading = false;
    for (HtmlHeading4 heading : headings) {
      String headingText = heading.getTextContent();
      if (headingText.contains("Snyk")) {
        foundHeading = true;
        assertEquals("Danger alert:Snyk: Server Error: This is an example error", headingText);
        break;
      }
    }
    assertTrue(foundHeading, "No heading with 'Snyk' found for hmtl error");
    // Select the Snyk Source
    HtmlButton snykSourceBtn = page.getFirstByXPath("//button[@aria-label='snyk source']");
    assertNotNull(snykSourceBtn);
    page = click(webClient, snykSourceBtn);
    final String pageAsText = page.asNormalizedText();
    assertTrue(pageAsText.contains("No results found"));

    verifySnykRequest(ERROR_TOKEN);
    verifyNoInteractionsWithOSS();
  }

  @Test
  public void testBatchHtmlWithToken() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON)
            .body(loadBatchSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.SNYK_TOKEN_HEADER, OK_TOKEN)
            .header(Constants.OSS_INDEX_USER_HEADER, OK_USER)
            .header(Constants.OSS_INDEX_TOKEN_HEADER, OK_TOKEN)
            .when()
            .post("/api/v4/batch-analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.TEXT_HTML)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .asString();

    var webClient = initWebClient();
    HtmlPage page = extractPage(webClient, body);
    // Find the root div element with id "root"
    HtmlElement rootElement = page.getFirstByXPath("//div[@id='root']");

    // Verify multi tab layout
    List<HtmlElement> sectionElements = rootElement.getByXPath("./section");
    assertEquals(1, sectionElements.size());
    List<HtmlAnchor> anchorElements =
        page.getByXPath(
            "//a[contains(@href, 'https://catalog.redhat.com/software/containers/ubi9/')]");
    assertTrue(!anchorElements.isEmpty(), "At least one href contains the desired substring");

    verifySnykRequest(OK_TOKEN, 3);
    verifyOssRequest(OK_USER, OK_TOKEN, 3);
  }

  private HtmlTableBody getTableBodyForDependency(String depRef, DomElement table) {
    List<HtmlTableBody> tbodies = table.getByXPath(".//tbody");
    return tbodies.stream()
        .filter(
            tbody -> {
              HtmlAnchor a = tbody.getFirstByXPath("./tr/th/a");
              return a.getTextContent().equals(depRef);
            })
        .findFirst()
        .orElse(null);
  }

  private HtmlPage expandTransitiveTableDataCell(WebClient webClient, HtmlTableBody tbody) {
    return expandTableDataCell(webClient, tbody, "Transitive Vulnerabilities");
  }

  private HtmlPage expandDirectTableDataCell(WebClient webClient, HtmlTableBody tbody) {
    return expandTableDataCell(webClient, tbody, "Direct Vulnerabilities");
  }

  private HtmlPage expandTableDataCell(WebClient webClient, HtmlTableBody tbody, String dataLabel) {
    HtmlTableDataCell td =
        tbody.getFirstByXPath(String.format("./tr/td[@data-label='%s']", dataLabel));
    if (td.getAttribute("class").contains("pf-m-expanded")) {
      return tbody.getHtmlPageOrNull();
    }
    HtmlButton button = td.getFirstByXPath("./button");
    return click(webClient, button);
  }

  private HtmlTable getIssuesTable(HtmlTableBody dependencyTable) {
    List<HtmlTableRow> rows = dependencyTable.getByXPath("./tr");
    if (rows.size() != 2) {
      fail(
          "Expected table to have 2 <tr>. One for the dependency name and another for the"
              + " vulnerabilities. Found: "
              + rows.size());
    }
    return rows.get(1).getFirstByXPath("//table");
  }

  private WebClient initWebClient() {
    WebClient webClient = new WebClient(BrowserVersion.BEST_SUPPORTED);
    webClient.getOptions().setJavaScriptEnabled(true);
    webClient.getOptions().setThrowExceptionOnScriptError(true);

    return webClient;
  }

  private HtmlPage extractPage(WebClient webClient, String html) {
    HtmlPage page = null;
    try {
      page = webClient.loadHtmlCodeIntoCurrentWindow(html);
    } catch (IOException e) {
      fail("The string is not valid HTML.", e);
    }
    webClient.waitForBackgroundJavaScript(50000);
    assertTrue(page.isHtmlPage(), "The string is valid HTML.");
    assertEquals("Dependency Analysis", page.getTitleText());
    assertNotNull(page.getElementsById("root"));
    assertNotNull(
        page.getFirstByXPath(
            "//section[contains(@class, 'pf-v5-c-page__main-section pf-m-light')]"));
    return page;
  }

  private HtmlPage click(WebClient webClient, HtmlButton button) {

    try {
      button.click();
    } catch (IOException e) {
      fail("Unexpected error clicking button");
    }
    webClient.waitForBackgroundJavaScript(1000); // Adjust timeout as needed
    return (HtmlPage) button.getPage();
  }
}
