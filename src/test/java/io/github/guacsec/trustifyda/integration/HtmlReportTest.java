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

import static io.github.guacsec.trustifyda.extensions.WiremockExtension.TRUSTIFY_TOKEN;
import static io.restassured.RestAssured.given;
import static org.apache.camel.Exchange.CONTENT_TYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.List;

import org.hamcrest.text.MatchesPattern;
import org.htmlunit.BrowserVersion;
import org.htmlunit.WebClient;
import org.htmlunit.html.DomElement;
import org.htmlunit.html.DomNodeList;
import org.htmlunit.html.HtmlAnchor;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlHeading4;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlTableBody;
import org.htmlunit.html.HtmlTableDataCell;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

import jakarta.ws.rs.core.MediaType;

@QuarkusTest
public class HtmlReportTest extends AbstractAnalysisTest {

  private static final String CYCLONEDX = "cyclonedx";

  @Test
  public void testHtmlWithoutToken() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .when()
            .post("/api/v5/analysis")
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
    HtmlButton srcBtn = page.getFirstByXPath("//button[@aria-label='trustify/csaf source']");
    assertNotNull(srcBtn);

    page = click(webClient, srcBtn);

    DomNodeList<DomElement> tables = page.getElementsByTagName("table");
    assertEquals(3, tables.size()); // osv | trustify/osv | trustify/csaf
    DomElement table = tables.get(tables.size() - 1); // trustify/csaf
    HtmlTableBody tbody = getTableBodyForDependency("io.quarkus:quarkus-hibernate-orm", table);
    assertNotNull(tbody);
    page = expandTransitiveTableDataCell(webClient, tbody);

    table =
        page.getFirstByXPath(
            "//table[contains(@aria-label, 'trustify/csaf transitive vulnerabilities')]");
    List<HtmlTableBody> tbodies = table.getByXPath(".//tbody");
    HtmlTableBody issue =
        tbodies.stream()
            .filter(
                issuesTbody -> {
                  List<HtmlAnchor> tds = issuesTbody.getByXPath("./tr/td");
                  return tds.size() == 6;
                })
            .findFirst()
            .get();
    assertNotNull(issue);

    verifyTrustifyRequest(TRUSTIFY_TOKEN);
  }

  @Test
  public void testHtmlUnauthorized() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, INVALID_TOKEN)
            .when()
            .post("/api/v5/analysis")
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
        "Warning alert:Trustify: Unauthorized: Verify the provided credentials are valid.",
        heading.getTextContent());

    // Select the Trustify Source
    HtmlButton srcBtn = page.getFirstByXPath("//button[@aria-label='trustify source']");
    assertNotNull(srcBtn);
    page = click(webClient, srcBtn);
    final String pageAsText = page.asNormalizedText();
    assertTrue(pageAsText.contains("No results found"));

    verifyTrustifyRequest(INVALID_TOKEN);
  }

  @Test
  public void testHtmlForbidden() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, UNAUTH_TOKEN)
            .when()
            .post("/api/v5/analysis")
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
        "Warning alert:Trustify: Forbidden: The provided credentials don't have the required"
            + " permissions.",
        heading.getTextContent());

    // Select the TRUSTIFY Source
    HtmlButton srcBtn = page.getFirstByXPath("//button[@aria-label='trustify source']");
    assertNotNull(srcBtn);
    page = click(webClient, srcBtn);
    final String pageAsText = page.asNormalizedText();
    assertTrue(pageAsText.contains("No results found"));

    verifyTrustifyRequest(UNAUTH_TOKEN);
  }

  @Test
  public void testHtmlError() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, ERROR_TOKEN)
            .when()
            .post("/api/v5/analysis")
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
      if (headingText.contains("Trustify")) {
        foundHeading = true;
        assertEquals("Danger alert:Trustify: Server Error: Unexpected error", headingText);
        break;
      }
    }
    assertTrue(foundHeading, "No heading with 'TRUSTIFY' found for hmtl error");
    // Select the Trustify Source
    HtmlButton srcBtn = page.getFirstByXPath("//button[@aria-label='trustify source']");
    assertNotNull(srcBtn);
    page = click(webClient, srcBtn);
    final String pageAsText = page.asNormalizedText();
    assertTrue(pageAsText.contains("No results found"));

    verifyTrustifyRequest(ERROR_TOKEN);
  }

  @Test
  public void testBatchHtmlWithToken() throws IOException {
    stubAllProviders();

    String body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadBatchSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.TEXT_HTML)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, OK_TOKEN)
            .when()
            .post("/api/v5/batch-analysis")
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
        page.getByXPath("//a[contains(@href, 'https://test-catalog.example.com/containers/ubi9')]");
    assertTrue(!anchorElements.isEmpty(), "At least one href contains the desired substring");
    verifyTrustifyRequest(OK_TOKEN, 3);
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

  private HtmlPage expandTableDataCell(WebClient webClient, HtmlTableBody tbody, String dataLabel) {
    HtmlTableDataCell td =
        tbody.getFirstByXPath(String.format("./tr/td[@data-label='%s']", dataLabel));
    if (td.getAttribute("class").contains("pf-m-expanded")) {
      return tbody.getHtmlPageOrNull();
    }
    HtmlButton button = td.getFirstByXPath("./button");

    // Debug: Print button details
    System.err.println(
        "*** DEBUG: Found button: "
            + button.getAttribute("id")
            + ", aria-expanded: "
            + button.getAttribute("aria-expanded")
            + ", class: "
            + button.getAttribute("class")
            + " ***");

    return click(webClient, button);
  }

  private WebClient initWebClient() {
    WebClient webClient = new WebClient(BrowserVersion.BEST_SUPPORTED);
    webClient.getOptions().setJavaScriptEnabled(true);
    webClient.getOptions().setThrowExceptionOnScriptError(true);
    webClient.getOptions().setCssEnabled(false); // Disable CSS to avoid warnings
    webClient.getOptions().setPrintContentOnFailingStatusCode(false);

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
    assertNotNull(page, "Page should not be null");
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
