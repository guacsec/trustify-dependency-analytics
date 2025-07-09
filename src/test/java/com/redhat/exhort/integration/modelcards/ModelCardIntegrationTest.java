/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.modelcards;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.redhat.exhort.api.v4.ListModelCardResponse;
import com.redhat.exhort.api.v4.ModelCardQueryItem;
import com.redhat.exhort.api.v4.ModelCardQueryRequest;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class ModelCardIntegrationTest {

  @Test
  public void testListModelCards() {
    var request = new ModelCardQueryRequest();
    var queryItem = new ModelCardQueryItem();
    queryItem.setModelName("microsoft/phi-2");
    var notFoundItem = new ModelCardQueryItem();
    notFoundItem.setModelName("not-found");
    request.addQueriesItem(queryItem);
    request.addQueriesItem(notFoundItem);

    List<ListModelCardResponse> responses =
        given()
            .contentType("application/json")
            .when()
            .body(request)
            .post("/api/v4/model-cards")
            .then()
            .statusCode(200)
            .extract()
            .body()
            .jsonPath()
            .getList(".", ListModelCardResponse.class);

    assertNotNull(responses);
    assertEquals(1, responses.size()); // Only one should be found
  }

  @Test
  public void testGetModelCard() {
    given()
        .when()
        .get("/api/v4/model-cards/550e8400-e29b-41d4-a716-446655440004")
        .then()
        .statusCode(200);
  }

  @Test
  public void testGetModelCard_NotFound() {
    given()
        .when()
        .get("/api/v4/model-cards/550e8400-e29b-41d4-a716-446655440007")
        .then()
        .statusCode(404);
  }
}
