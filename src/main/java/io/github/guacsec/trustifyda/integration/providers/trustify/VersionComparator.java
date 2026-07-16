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

import java.util.Comparator;
import java.util.regex.Pattern;

enum VersionComparator implements Comparator<String> {
  INSTANCE;

  private static final Pattern SPLIT = Pattern.compile("[.\\-]");

  @Override
  public int compare(String a, String b) {
    if (a == null && b == null) return 0;
    if (a == null) return -1;
    if (b == null) return 1;

    String[] partsA = SPLIT.split(a);
    String[] partsB = SPLIT.split(b);
    int len = Math.max(partsA.length, partsB.length);

    for (int i = 0; i < len; i++) {
      String sa = i < partsA.length ? partsA[i] : "";
      String sb = i < partsB.length ? partsB[i] : "";
      int cmp = comparePart(sa, sb);
      if (cmp != 0) return cmp;
    }
    return 0;
  }

  private static int comparePart(String a, String b) {
    boolean aNum = isNumeric(a);
    boolean bNum = isNumeric(b);
    if (aNum && bNum) {
      return Long.compare(Long.parseLong(a), Long.parseLong(b));
    }
    if (aNum) return -1;
    if (bNum) return 1;
    return a.compareToIgnoreCase(b);
  }

  private static boolean isNumeric(String s) {
    if (s.isEmpty()) return false;
    for (int i = 0; i < s.length(); i++) {
      if (!Character.isDigit(s.charAt(i))) return false;
    }
    return true;
  }
}
