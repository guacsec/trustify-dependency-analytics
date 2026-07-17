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

package io.github.guacsec.trustifyda.integration.providers.trustify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

public class VersionComparatorTest {

  private final VersionComparator comparator = VersionComparator.INSTANCE;

  @Test
  void bothNullReturnsZero() {
    assertEquals(0, comparator.compare(null, null));
  }

  @Test
  void leftNullComesFirst() {
    assertTrue(comparator.compare(null, "1.0") < 0);
  }

  @Test
  void rightNullComesLast() {
    assertTrue(comparator.compare("1.0", null) > 0);
  }

  @Test
  void equalVersionsReturnZero() {
    assertEquals(0, comparator.compare("1.2.3", "1.2.3"));
  }

  @Test
  void numericPartsComparedNumerically() {
    assertTrue(comparator.compare("1.2.3", "1.2.10") < 0);
    assertTrue(comparator.compare("2.0.0", "1.9.9") > 0);
  }

  @Test
  void differentLengthVersions() {
    // missing part is "" (non-numeric) vs "1" (numeric) — numeric sorts first
    assertTrue(comparator.compare("1.0", "1.0.1") > 0);
    assertTrue(comparator.compare("1.0.1", "1.0") < 0);
  }

  @Test
  void hyphenSeparator() {
    assertTrue(comparator.compare("1.0-alpha", "1.0-beta") < 0);
    assertEquals(0, comparator.compare("1.0-rc1", "1.0-rc1"));
  }

  @Test
  void numericBeforeString() {
    // numeric parts sort before string parts
    assertTrue(comparator.compare("1", "alpha") < 0);
    assertTrue(comparator.compare("alpha", "1") > 0);
  }

  @Test
  void stringPartsAreCaseInsensitive() {
    assertEquals(0, comparator.compare("1.0-ALPHA", "1.0-alpha"));
    assertEquals(0, comparator.compare("1.0-Beta", "1.0-BETA"));
  }

  @Test
  void mixedSeparators() {
    assertTrue(comparator.compare("1.0-1", "1.0-2") < 0);
    assertTrue(comparator.compare("1.0.1-beta", "1.0.2-alpha") < 0);
  }

  @Test
  void sortingProducesExpectedOrder() {
    List<String> versions = Arrays.asList("2.0.0", "1.0.0", "1.0.1", "1.10.0", "1.2.0");
    versions.sort(comparator);
    assertEquals(List.of("1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0"), versions);
  }

  @Test
  void emptyStringHandledGracefully() {
    // empty string is non-numeric, so numeric "1" sorts before it
    assertTrue(comparator.compare("", "1.0") > 0);
    assertTrue(comparator.compare("1.0", "") < 0);
    assertEquals(0, comparator.compare("", ""));
  }
}
