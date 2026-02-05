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

import java.util.Optional;
import java.util.function.Predicate;

import io.quarkus.runtime.annotations.RegisterForReflection;

/** Utility class for exception handling and traversal. */
@RegisterForReflection
public class ExceptionUtils {

  private ExceptionUtils() {}

  /**
   * Searches for a specific exception type in the exception chain.
   *
   * @param exception the root exception
   * @param targetType the exception class to search for
   * @return Optional containing the found exception, or empty if not found
   */
  public static <T extends Throwable> Optional<T> findInChain(
      Throwable exception, Class<T> targetType) {
    Throwable current = exception;
    while (current != null) {
      if (targetType.isInstance(current)) {
        return Optional.of(targetType.cast(current));
      }
      current = current.getCause();
    }
    return Optional.empty();
  }

  /**
   * Searches for an exception matching the given predicate in the exception chain.
   *
   * @param exception the root exception
   * @param matcher predicate to test each exception in the chain
   * @return Optional containing the found exception, or empty if not found
   */
  public static Optional<Throwable> findInChain(Throwable exception, Predicate<Throwable> matcher) {
    Throwable current = exception;
    while (current != null) {
      if (matcher.test(current)) {
        return Optional.of(current);
      }
      current = current.getCause();
    }
    return Optional.empty();
  }

  /**
   * Extracts the longest message from the exception chain.
   *
   * @param exception the root exception
   * @return the longest message found in the chain, or the exception class name if no message
   *     exists
   */
  public static String getLongestMessage(Throwable exception) {
    String longestMessage = exception.getMessage();
    Throwable current = exception.getCause();
    while (current != null) {
      String msg = current.getMessage();
      if (msg != null && (longestMessage == null || msg.length() > longestMessage.length())) {
        longestMessage = msg;
      }
      current = current.getCause();
    }
    return longestMessage != null ? longestMessage : exception.getClass().getSimpleName();
  }
}
