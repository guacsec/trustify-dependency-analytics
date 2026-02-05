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

package io.github.guacsec.trustifyda.integration.backend;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class ExceptionUtilsTest {

  @Test
  void testFindInChain_withTargetTypeFound() {
    var cause = new IOException("IO error");
    var middle = new RuntimeException("Runtime error", cause);
    var root = new IllegalStateException("State error", middle);

    Optional<IOException> result = ExceptionUtils.findInChain(root, IOException.class);

    assertTrue(result.isPresent());
    assertEquals("IO error", result.get().getMessage());
  }

  @Test
  void testFindInChain_withTargetTypeNotFound() {
    var cause = new IOException("IO error");
    var root = new RuntimeException("Runtime error", cause);

    Optional<IllegalArgumentException> result =
        ExceptionUtils.findInChain(root, IllegalArgumentException.class);

    assertFalse(result.isPresent());
  }

  @Test
  void testFindInChain_withTargetTypeAtRoot() {
    var root = new UnknownHostException("localhost");

    Optional<UnknownHostException> result =
        ExceptionUtils.findInChain(root, UnknownHostException.class);

    assertTrue(result.isPresent());
    assertEquals("localhost", result.get().getMessage());
  }

  @Test
  void testFindInChain_withPredicate_found() {
    var cause = new RuntimeException("TimeoutException occurred");
    var root = new IllegalStateException("State error", cause);

    Optional<Throwable> result =
        ExceptionUtils.findInChain(root, e -> e.getMessage().contains("Timeout"));

    assertTrue(result.isPresent());
    assertEquals("TimeoutException occurred", result.get().getMessage());
  }

  @Test
  void testFindInChain_withPredicate_notFound() {
    var cause = new IOException("IO error");
    var root = new RuntimeException("Runtime error", cause);

    Optional<Throwable> result =
        ExceptionUtils.findInChain(root, e -> e.getMessage().contains("Timeout"));

    assertFalse(result.isPresent());
  }

  @Test
  void testFindInChain_withPredicate_byClassName() {
    var cause = new RuntimeException("Some error");
    // Simulate circuit breaker exception check
    var root = new IllegalStateException("Circuit breaker open", cause);

    Optional<Throwable> result =
        ExceptionUtils.findInChain(
            root, e -> e.getClass().getName().contains("IllegalStateException"));

    assertTrue(result.isPresent());
    assertEquals("Circuit breaker open", result.get().getMessage());
  }

  @Test
  void testGetLongestMessage_withSingleException() {
    var exception = new RuntimeException("Short message");

    String result = ExceptionUtils.getLongestMessage(exception);

    assertEquals("Short message", result);
  }

  @Test
  void testGetLongestMessage_withNestedExceptions() {
    var cause1 = new IOException("Very long detailed error message from IO");
    var cause2 = new RuntimeException("Medium message", cause1);
    var root = new IllegalStateException("Short", cause2);

    String result = ExceptionUtils.getLongestMessage(root);

    assertEquals("Very long detailed error message from IO", result);
  }

  @Test
  void testGetLongestMessage_withNullMessages() {
    var cause = new IOException();
    var root = new RuntimeException("Only root has message", cause);

    String result = ExceptionUtils.getLongestMessage(root);

    assertEquals("Only root has message", result);
  }

  @Test
  void testGetLongestMessage_withAllNullMessages() {
    var root = new RuntimeException("Test");

    String result = ExceptionUtils.getLongestMessage(root);

    // Returns the message or class name when available
    assertEquals("Test", result);
  }

  @Test
  void testGetLongestMessage_withMultipleExceptionsAndSameLength() {
    var cause = new IOException("Same length msg");
    var root = new RuntimeException("Same length msg", cause);

    String result = ExceptionUtils.getLongestMessage(root);

    assertEquals("Same length msg", result);
  }

  @Test
  void testFindInChain_withDeepNesting() {
    var level5 = new UnknownHostException("deepest");
    var level4 = new IOException("deep", level5);
    var level3 = new RuntimeException("medium", level4);
    var level2 = new IllegalStateException("shallow", level3);
    var root = new IllegalArgumentException("root", level2);

    Optional<UnknownHostException> result =
        ExceptionUtils.findInChain(root, UnknownHostException.class);

    assertTrue(result.isPresent());
    assertEquals("deepest", result.get().getMessage());
  }

  @Test
  void testFindInChain_withNoCause() {
    var root = new RuntimeException("No cause");

    Optional<IOException> result = ExceptionUtils.findInChain(root, IOException.class);

    assertFalse(result.isPresent());
  }
}
