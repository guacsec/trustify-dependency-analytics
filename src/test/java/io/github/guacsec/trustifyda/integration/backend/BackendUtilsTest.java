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

import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BackendUtilsTest {

  private BackendUtils backendUtils;
  private BackendUtils backendUtilsFakeTimer;
  private static final int numberOfRequests = 10000;

  @BeforeEach
  void setUp() {
    this.backendUtils = new BackendUtils();
    LocalDate fakeDate = LocalDate.of(2024, 1, 1);
    Clock clock =
        Clock.fixed(fakeDate.atStartOfDay().toInstant(ZoneOffset.UTC), ZoneId.systemDefault());
    this.backendUtilsFakeTimer = new BackendUtils(clock);
  }

  @Test
  void checkGeneratedWithLengthOf64AndHexaDecimalString() {

    String requestId = this.backendUtils.generateRequestId(UUID.randomUUID().toString());
    assertTrue(requestId.length() == 64);
    assertTrue(allCharactersAreHexaDecimalDigits(requestId));
  }

  private boolean allCharactersAreHexaDecimalDigits(String requestId) {

    return Arrays.stream(ArrayUtils.toObject(requestId.getBytes(StandardCharsets.UTF_8)))
            .filter(
                t -> // character is hexadecimal digit a-f
                (t.shortValue() >= 97 && t.shortValue() <= 102)
                        // or char is one of 0-9 digits.
                        || (t.shortValue() >= 48 && (t.shortValue() <= 57)))
            .collect(Collectors.toList())
            .size()
        == requestId.length();
  }

  @Test
  void checkGeneratedWithNoRHDATokenAndShouldBeDifferentFromEachOther() {

    String reqId1 = this.backendUtils.generateRequestId(null);
    String reqId2 = this.backendUtils.generateRequestId(null);
    assertFalse(reqId1.equals(reqId2));
  }

  @Test
  void checkGeneratedWithSameUuidRHDATokenAndDifferentTimeShouldBeDifferentFromEachOther() {

    String randomUUID = UUID.randomUUID().toString();
    String reqId1 = this.backendUtils.generateRequestId(randomUUID);
    String reqId2 = this.backendUtils.generateRequestId(randomUUID);
    assertFalse(reqId1.equals(reqId2));
  }

  @Test
  void checkGeneratedWithSameTimeDifferentRHDATokenAndDifferentFromEachOther()
      throws InterruptedException {

    String randomUUID = UUID.randomUUID().toString();
    String randomUUID2 = UUID.randomUUID().toString();
    AtomicReference<String> reqId = new AtomicReference<>();
    AtomicReference<String> reqId2 = new AtomicReference<>();
    Thread thread = createThread(reqId, randomUUID);
    Thread thread2 = createThread(reqId2, randomUUID2);
    thread.start();
    thread2.start();
    thread.join();
    thread2.join();
    assertFalse(reqId.get().equals(reqId2.get()));
  }

  @Test
  void checkGeneratedWithSameTimeSameRHDATokenAndTheyShouldBeEquals() throws InterruptedException {

    String randomUUID = UUID.randomUUID().toString();

    AtomicReference<String> reqId = new AtomicReference<>();
    AtomicReference<String> reqId2 = new AtomicReference<>();
    Thread thread = createThread(reqId, randomUUID);
    Thread thread2 = createThread(reqId2, randomUUID);
    thread.start();
    thread2.start();
    thread.join();
    thread2.join();
    assertTrue(reqId.get().equals(reqId2.get()));
  }

  @Test
  void checkGeneratedWithSameTimeWithNullRHDATokenAndTheyShouldBeDifferent()
      throws InterruptedException {

    AtomicReference<String> reqId = new AtomicReference<>();
    AtomicReference<String> reqId2 = new AtomicReference<>();
    Thread thread = createThread(reqId, null);
    Thread thread2 = createThread(reqId2, null);
    thread.start();
    thread2.start();
    thread.join();
    thread2.join();
    assertNotEquals(reqId.get(), reqId2.get());
  }

  @Test
  void checkMassGeneratedConcurrentlyWithDifferentRHDATokensAndAllShouldBeDifferentFromEachOther()
      throws InterruptedException, ExecutionException, TimeoutException {
    Executor executor = Executors.newCachedThreadPool();
    List<CompletableFuture<String>> futuresReqIds = new ArrayList<>();
    Set<String> results = ConcurrentHashMap.newKeySet();
    for (int i = 0; i < numberOfRequests; i++) {
      futuresReqIds.add(
          CompletableFuture.supplyAsync(
                  () -> this.backendUtils.generateRequestId(UUID.randomUUID().toString()), executor)
              .whenComplete(
                  (reqId, error) -> {
                    if (results.contains(reqId)) {
                      fail("Found duplicate key: " + reqId);
                    } else {
                      results.add(reqId);
                    }
                  }));
    }
    CompletableFuture.allOf(futuresReqIds.toArray(new CompletableFuture[0]))
        .get(5, TimeUnit.SECONDS);
    assertEquals(numberOfRequests, results.size());
  }

  private Thread createThread(AtomicReference<String> reqId, String rhdaToken) {
    return new Thread(() -> reqId.set(this.backendUtilsFakeTimer.generateRequestId(rhdaToken)));
  }
}
