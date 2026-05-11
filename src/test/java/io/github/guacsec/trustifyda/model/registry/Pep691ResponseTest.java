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

package io.github.guacsec.trustifyda.model.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Pep691ResponseTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void deserializeFullResponse() throws Exception {
    String json =
        """
        {
          "name": "requests",
          "files": [
            {
              "filename": "requests-2.31.0-py3-none-any.whl",
              "url": "https://example.com/requests-2.31.0-py3-none-any.whl",
              "hashes": {
                "sha256": "abc123def456"
              }
            }
          ]
        }
        """;

    Pep691Response response = mapper.readValue(json, Pep691Response.class);

    assertEquals("requests", response.name());
    assertNotNull(response.files());
    assertEquals(1, response.files().size());
    assertEquals("requests-2.31.0-py3-none-any.whl", response.files().get(0).filename());
    assertEquals("abc123def456", response.files().get(0).hashes().get("sha256"));
  }

  @Test
  void deserializeIgnoresUnknownFields() throws Exception {
    String json =
        """
        {
          "meta": {"api-version": "1.1"},
          "name": "flask",
          "files": [
            {
              "filename": "flask-3.0.0.tar.gz",
              "url": "https://example.com/flask-3.0.0.tar.gz",
              "hashes": {"sha256": "deadbeef"},
              "requires-python": ">=3.8",
              "dist-info-metadata": true
            }
          ]
        }
        """;

    Pep691Response response = mapper.readValue(json, Pep691Response.class);

    assertEquals("flask", response.name());
    assertEquals(1, response.files().size());
    assertEquals("deadbeef", response.files().get(0).hashes().get("sha256"));
  }

  @Test
  void deserializeMultipleFiles() throws Exception {
    String json =
        """
        {
          "name": "pip",
          "files": [
            {"filename": "pip-23.0.tar.gz", "url": "https://example.com/pip-23.0.tar.gz", "hashes": {"sha256": "aaa"}},
            {"filename": "pip-23.1.tar.gz", "url": "https://example.com/pip-23.1.tar.gz", "hashes": {"sha256": "bbb"}},
            {"filename": "pip-23.1-py3-none-any.whl", "url": "https://example.com/pip-23.1-py3-none-any.whl", "hashes": {"sha256": "ccc"}}
          ]
        }
        """;

    Pep691Response response = mapper.readValue(json, Pep691Response.class);

    assertEquals(3, response.files().size());
    assertEquals("aaa", response.files().get(0).hashes().get("sha256"));
    assertEquals("bbb", response.files().get(1).hashes().get("sha256"));
    assertEquals("ccc", response.files().get(2).hashes().get("sha256"));
  }
}
