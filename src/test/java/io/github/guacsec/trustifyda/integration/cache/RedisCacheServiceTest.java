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

package io.github.guacsec.trustifyda.integration.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.LicenseCategory;
import io.github.guacsec.trustifyda.api.v5.PackageLicenseResult;
import io.github.guacsec.trustifyda.integration.licenses.SpdxLicenseService;
import io.github.guacsec.trustifyda.model.licenses.LicenseSplitResult;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.inject.Inject;

/** Regression tests for package-license cache compatibility across rolling deployments. */
@QuarkusTest
class RedisCacheServiceTest {

  @Inject RedisDataSource redis;
  @Inject CacheService cache;
  @Inject ObjectMapper mapper;
  @Inject SpdxLicenseService classifier;

  @ConfigProperty(name = "licenses.cache.ttl", defaultValue = "1d")
  Duration configuredTtl;

  @TempDir Path configurationDirectory;

  private final Set<String> writtenKeys = new HashSet<>();

  @AfterEach
  void removeTestKeys() {
    if (!writtenKeys.isEmpty()) {
      redis.key().del(writtenKeys.toArray(String[]::new));
    }
  }

  /**
   * Verifies legacy mapping and flattened-expression values are misses, then caches recomputation.
   */
  @ParameterizedTest
  @CsvSource(
      delimiter = '|',
      value = {
        "Unicode-DFS-2016 | UNKNOWN | PERMISSIVE",
        "Unlicense | UNKNOWN | PERMISSIVE",
        "CC0-1.0 | UNKNOWN | PERMISSIVE",
        "GPL-3.0 AND (MIT OR Apache-2.0) | PERMISSIVE | STRONG_COPYLEFT"
      })
  void legacyClassificationsAreMisses(
      String expression, LicenseCategory oldCategory, LicenseCategory currentCategory)
      throws Exception {
    // Given the exact unversioned key and ref/result JSON shape used by old binaries
    var ref = packageRef();
    writeRaw(legacyKey(ref), ref, result(expression, oldCategory));

    // When a current reader looks up that same package
    var hits = cache.getCachedLicenses(Set.of(ref));

    // Then the old classification is a miss and a real classifier result becomes a compatible hit
    assertTrue(hits.isEmpty(), "Current readers must ignore unversioned classifications");
    var recomputed = result(classifier, expression);
    assertEquals(currentCategory, recomputed.getConcluded().getCategory());
    writeCurrent(cache, classifier, ref, recomputed);
    assertEquals(Map.of(ref, recomputed), cache.getCachedLicenses(Set.of(ref)));
  }

  /** Verifies overlapping misses are safe when the unchanged legacy writer completes last. */
  @Test
  void legacyWriterFinishingLastCannotOverwriteCurrentResult() throws Exception {
    // Given both readers missed before either in-flight computation completes
    var ref = packageRef();
    assertTrue(cache.getCachedLicenses(Set.of(ref)).isEmpty());
    assertNull(redis.execute("GET", legacyKey(ref)));
    var oldResult = result("Unicode-DFS-2016", LicenseCategory.UNKNOWN);
    var currentResult = result(classifier, "Unicode-DFS-2016");

    // When the current write finishes first, followed deliberately by the old raw Redis write
    writeCurrent(cache, classifier, ref, currentResult);
    writeRaw(legacyKey(ref), ref, oldResult);

    // Then the late old write exists but cannot change the current reader's PERMISSIVE result
    assertNotNull(redis.execute("GET", legacyKey(ref)));
    assertEquals(LicenseCategory.PERMISSIVE, currentResult.getConcluded().getCategory());
    assertEquals(Map.of(ref, currentResult), cache.getCachedLicenses(Set.of(ref)));
  }

  /**
   * Verifies legacy repopulation after targeted invalidation cannot restore a stale current hit.
   */
  @Test
  void legacyRepopulationAfterInvalidationRemainsIsolated() throws Exception {
    // Given a compatible entry that is invalidated by its exact key
    var ref = packageRef();
    var currentResult = result(classifier, "Unlicense");
    writeCurrent(cache, classifier, ref, currentResult);
    redis.key().del(currentKey(classifier, ref));

    // When an unchanged old writer repopulates its legacy key
    writeRaw(legacyKey(ref), ref, result("Unlicense", LicenseCategory.UNKNOWN));

    // Then the current reader still misses and can recompute a compatible value
    assertTrue(cache.getCachedLicenses(Set.of(ref)).isEmpty());
    writeCurrent(cache, classifier, ref, result(classifier, "Unlicense"));
    assertEquals(Map.of(ref, currentResult), cache.getCachedLicenses(Set.of(ref)));
  }

  /** Verifies incompatible classifier revisions do not share results even with identical rules. */
  @Test
  void identicalMappingsWithOldClassifierRevisionAreIsolated() throws Exception {
    // Given the SAME mapping fingerprint, but the old flattened classifier's PERMISSIVE result
    var ref = packageRef();
    String identity = classifier.getCacheCompatibilityIdentity();
    String fingerprint = identity.substring(identity.lastIndexOf(':') + 1);
    String oldKey = "licenses:v1:flattened-v1:" + fingerprint + ":" + ref.purl().getCoordinates();
    String mappingOnlyKey = "licenses:v1:" + fingerprint + ":" + ref.purl().getCoordinates();
    assertNotEquals(oldKey, currentKey(classifier, ref));
    String expression = "GPL-3.0 AND (MIT OR Apache-2.0)";
    writeRaw(oldKey, ref, result(expression, LicenseCategory.PERMISSIVE));
    writeRaw(mappingOnlyKey, ref, result(expression, LicenseCategory.PERMISSIVE));

    // When a current reader recomputes instead of trusting the old classifier
    assertTrue(cache.getCachedLicenses(Set.of(ref)).isEmpty());
    var corrected = result(classifier, expression);
    writeCurrent(cache, classifier, ref, corrected);
    writeRaw(oldKey, ref, result(expression, LicenseCategory.PERMISSIVE));

    // Then the corrected aggregate and individual SPDX metadata survive a cache hit
    assertEquals(LicenseCategory.STRONG_COPYLEFT, corrected.getConcluded().getCategory());
    assertEquals(Map.of(ref, corrected), cache.getCachedLicenses(Set.of(ref)));
    assertEquals(
        Set.of("GPL-3.0", "MIT", "Apache-2.0"),
        corrected.getConcluded().getIdentifiers().stream()
            .map(identifier -> identifier.getId())
            .collect(java.util.stream.Collectors.toSet()));
  }

  /**
   * Verifies incompatible cached-value formats are not read, even with identical classifier rules.
   */
  @Test
  void incompatibleCacheFormatIsAMiss() {
    // Given an incompatible format namespace containing a value current code cannot deserialize
    var ref = packageRef();
    String key =
        "licenses:v0:"
            + classifier.getCacheCompatibilityIdentity()
            + ":"
            + ref.purl().getCoordinates();
    writtenKeys.add(key);
    redis.execute("PSETEX", key, "86400000", "not-current-json");

    // When reading the current format
    var hits = cache.getCachedLicenses(Set.of(ref));

    // Then the incompatible entry is never deserialized or consumed
    assertTrue(hits.isEmpty());
  }

  /** Verifies every effective rules dimension from a categories.file override isolates results. */
  @ParameterizedTest
  @MethodSource("changedMappings")
  void changedEffectiveMappingsAreIsolated(
      String oldYaml, String currentYaml, String expression, LicenseCategory expectedCategory)
      throws Exception {
    // Given two real file overrides with one relevant rules change and a shared Redis instance
    var oldClassifier = classifierFor(oldYaml);
    var currentClassifier = classifierFor(currentYaml);
    var oldCache = cacheFor(oldClassifier);
    var currentCache = cacheFor(currentClassifier);
    var ref = packageRef();
    var oldResult = result(oldClassifier, expression);
    writeCurrent(oldCache, oldClassifier, ref, oldResult);
    assertNotEquals(
        oldClassifier.getCacheCompatibilityIdentity(),
        currentClassifier.getCacheCompatibilityIdentity());

    // When the changed configuration reads, computes, and writes its own result
    assertTrue(currentCache.getCachedLicenses(Set.of(ref)).isEmpty());
    var currentResult = result(currentClassifier, expression);
    writeCurrent(currentCache, currentClassifier, ref, currentResult);
    writeCurrent(oldCache, oldClassifier, ref, oldResult);

    // Then a late incompatible writer cannot poison the current namespace
    assertEquals(expectedCategory, currentResult.getConcluded().getCategory());
    assertNotEquals(
        oldResult.getConcluded().getCategory(), currentResult.getConcluded().getCategory());
    assertEquals(Map.of(ref, currentResult), currentCache.getCachedLicenses(Set.of(ref)));
    redis.key().del(currentKey(currentClassifier, ref));
    writeCurrent(oldCache, oldClassifier, ref, oldResult);
    assertTrue(currentCache.getCachedLicenses(Set.of(ref)).isEmpty());
  }

  /**
   * Verifies order, duplicates, comments, shadowed memberships and exception case preserve hits.
   */
  @Test
  void equivalentEffectiveConfigurationSharesCache() throws Exception {
    // Given semantically equivalent rules loaded from different files
    var first =
        classifierFor(yaml("MIT, Apache-2.0", "LGPL-2.1", "GPL-3.0", "Classpath-exception-2.0"));
    var equivalent =
        classifierFor(
            "# Equivalent effective rules, different bytes and filename\n"
                + yaml(
                    "Apache-2.0, MIT, MIT",
                    "MIT, LGPL-2.1",
                    "MIT, LGPL-2.1, GPL-3.0",
                    "classpath-exception-2.0, CLASSPATH-EXCEPTION-2.0"));
    var ref = packageRef();
    var expected = result(first, "MIT");

    // When one pod writes and an equivalently configured pod reads
    writeCurrent(cacheFor(first), first, ref, expected);

    // Then equivalent effective rules share a stable identity and the actual cached value
    assertEquals(first.getCacheCompatibilityIdentity(), equivalent.getCacheCompatibilityIdentity());
    assertEquals(Map.of(ref, expected), cacheFor(equivalent).getCachedLicenses(Set.of(ref)));
  }

  /**
   * Verifies a file override with the bundled effective rules has the same compatibility identity.
   */
  @Test
  void fileOverrideWithBundledRulesSharesIdentity() throws Exception {
    // Given the actual bundled rules copied to an external categories.file override
    String bundled;
    try (var stream = getClass().getClassLoader().getResourceAsStream("license-categories.yaml")) {
      assertNotNull(stream);
      bundled = new String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    }
    var external = classifierFor("# External override\n" + bundled);

    // When comparing the classpath-loaded and file-loaded rules
    assertEquals(
        classifier.getCacheCompatibilityIdentity(), external.getCacheCompatibilityIdentity());
  }

  /** Verifies omitted optional exceptions and an empty list are equivalent effective rules. */
  @Test
  void absentAndEmptyExceptionsShareIdentity() throws Exception {
    var absent =
        classifierFor("permissive: [MIT]\nweak-copyleft: []\nstrong-copyleft: [GPL-3.0]\n");
    var empty = classifierFor(yaml("MIT", "", "GPL-3.0", ""));
    assertEquals(absent.getCacheCompatibilityIdentity(), empty.getCacheCompatibilityIdentity());
  }

  /** Verifies package identity still ignores qualifiers and cached SPDX metadata is unchanged. */
  @Test
  void coordinateIdentityAndMetadataArePreserved() {
    // Given a package result written using one qualifier
    String coordinate = "pkg:maven/org.example/tc7598-" + UUID.randomUUID() + "@1.0.0";
    var original = new PackageRef(coordinate + "?type=jar");
    var otherQualifier = new PackageRef(coordinate + "?type=pom");
    var expected = result(classifier, "CC0-1.0");
    writeCurrent(cache, classifier, original, expected);

    // When reading the same coordinates with another qualifier
    var hits = cache.getCachedLicenses(Set.of(otherQualifier));

    // Then the original cache contract and all metadata round-trip unchanged
    assertEquals(Map.of(original, expected), hits);
    assertEquals(
        Boolean.FALSE,
        hits.get(original).getConcluded().getIdentifiers().getFirst().getIsOsiApproved());
  }

  /**
   * Verifies the configured write TTL is preserved, reads do not renew it, and expired keys miss.
   */
  @ParameterizedTest
  @ValueSource(longs = {7200000, 172800000})
  void ttlIsConfiguredWithoutReadRenewal(long ttlMillis) {
    // Given a real cache with a configured TTL, bounded by Redis's own server clock
    var configuredCache = cacheFor(classifier);
    configuredCache.licenseTtl = Duration.ofMillis(ttlMillis);
    var ref = packageRef();
    String key = currentKey(classifier, ref);
    var expected = result(classifier, "MIT");
    long before = serverTimeMillis();
    writeCurrent(configuredCache, classifier, ref, expected);
    long after = serverTimeMillis();
    long expiry = redis.execute("PEXPIRETIME", key).toLong();
    assertTrue(expiry >= before + ttlMillis && expiry <= after + ttlMillis);

    // When a reader hits an entry with an intentionally shortened, exact expiry
    long shortenedExpiry = expiry - 60000;
    redis.execute("PEXPIREAT", key, Long.toString(shortenedExpiry));
    assertEquals(Map.of(ref, expected), configuredCache.getCachedLicenses(Set.of(ref)));

    // Then the read did not renew the expiry, and expiry in the past causes a miss without sleeps
    assertEquals(shortenedExpiry, redis.execute("PEXPIRETIME", key).toLong());
    redis.execute("PEXPIREAT", key, "1");
    assertTrue(configuredCache.getCachedLicenses(Set.of(ref)).isEmpty());
  }

  private static Stream<Arguments> changedMappings() {
    String empty = yaml("MIT", "", "", "");
    return Stream.of(
        Arguments.of(
            empty,
            yaml("MIT, Unicode-DFS-2016", "", "", ""),
            "Unicode-DFS-2016",
            LicenseCategory.PERMISSIVE),
        Arguments.of(
            empty, yaml("MIT", "LGPL-2.1", "", ""), "LGPL-2.1", LicenseCategory.WEAK_COPYLEFT),
        Arguments.of(
            empty, yaml("MIT", "", "GPL-3.0", ""), "GPL-3.0", LicenseCategory.STRONG_COPYLEFT),
        Arguments.of(
            yaml("MIT", "", "GPL-2.0", ""),
            yaml("MIT", "", "GPL-2.0", "Classpath-exception-2.0"),
            "GPL-2.0-only WITH Classpath-exception-2.0",
            LicenseCategory.WEAK_COPYLEFT));
  }

  private static String yaml(String permissive, String weak, String strong, String exceptions) {
    return "permissive: ["
        + permissive
        + "]\nweak-copyleft: ["
        + weak
        + "]\nstrong-copyleft: ["
        + strong
        + "]\nweak-copyleft-exceptions: ["
        + exceptions
        + "]\n";
  }

  private SpdxLicenseService classifierFor(String yaml) throws Exception {
    Path file = configurationDirectory.resolve(UUID.randomUUID() + ".yaml");
    Files.writeString(file, yaml);
    var service = new SpdxLicenseService();
    var property = SpdxLicenseService.class.getDeclaredField("categoriesFile");
    property.setAccessible(true);
    property.set(service, file.toString());
    var start = SpdxLicenseService.class.getDeclaredMethod("onStart", StartupEvent.class);
    start.setAccessible(true);
    start.invoke(service, new StartupEvent());
    return service;
  }

  private RedisCacheService cacheFor(SpdxLicenseService service) {
    var instance = new RedisCacheService(redis, service);
    instance.licenseTtl = configuredTtl;
    return instance;
  }

  private static PackageRef packageRef() {
    return new PackageRef("pkg:npm/tc-7598-" + UUID.randomUUID() + "@1.0.0");
  }

  private static String legacyKey(PackageRef ref) {
    return "licenses:" + ref.purl().getCoordinates();
  }

  private static String currentKey(SpdxLicenseService service, PackageRef ref) {
    return "licenses:v1:"
        + service.getCacheCompatibilityIdentity()
        + ":"
        + ref.purl().getCoordinates();
  }

  private static PackageLicenseResult result(SpdxLicenseService service, String expression) {
    var info = service.fromLicenseId(expression, "deps.dev", "https://api.deps.dev");
    return new PackageLicenseResult().concluded(info).evidence(List.of(info));
  }

  private PackageLicenseResult result(String expression, LicenseCategory category) {
    var info = classifier.fromLicenseId(expression, "deps.dev", "https://api.deps.dev");
    info.setCategory(category);
    if (info.getIdentifiers().size() == 1) {
      info.getIdentifiers().getFirst().setCategory(category);
    }
    return new PackageLicenseResult().concluded(info).evidence(List.of(info));
  }

  private void writeRaw(String key, PackageRef ref, PackageLicenseResult result) throws Exception {
    writtenKeys.add(key);
    redis.execute(
        "PSETEX", key, "86400000", mapper.writeValueAsString(Map.of("ref", ref, "result", result)));
  }

  private void writeCurrent(
      CacheService writer,
      SpdxLicenseService service,
      PackageRef ref,
      PackageLicenseResult result) {
    writtenKeys.add(currentKey(service, ref));
    writer.cacheLicenses(
        new LicenseSplitResult(null, Map.of(ref.purl().getCoordinates(), result)), Set.of(ref));
  }

  private long serverTimeMillis() {
    var time = redis.execute("TIME");
    return time.get(0).toLong() * 1000 + time.get(1).toLong() / 1000;
  }
}
