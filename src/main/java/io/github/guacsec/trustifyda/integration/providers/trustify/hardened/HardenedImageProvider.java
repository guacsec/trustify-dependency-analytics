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

package io.github.guacsec.trustifyda.integration.providers.trustify.hardened;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.jboss.logging.Logger;

import io.github.guacsec.trustifyda.integration.lock.LockService;
import io.github.guacsec.trustifyda.model.trustify.HardenedImageIndex;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;
import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import io.quarkus.scheduler.Scheduled;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Provider that periodically fetches hardened image compatibility data from the Hummingbird service
 * and maintains a thread-safe in-memory index for lookups. Delegates response parsing to {@link
 * HardenedImageResponseHandler} and distributed locking to {@link LockService}.
 */
@ApplicationScoped
public class HardenedImageProvider {

  private static final Logger LOG = Logger.getLogger(HardenedImageProvider.class);
  private static final String LOCK_KEY = "hardened-image-refresh-lock";

  private final HardenedImageIndex index = new HardenedImageIndex();
  private final HardenedImageRecommendation config;
  private final LockService lock;
  private final HardenedImageResponseHandler responseHandler;
  private final HummingbirdClient hummingbirdClient;

  public HardenedImageProvider(
      HardenedImageRecommendation config,
      LockService lock,
      HardenedImageResponseHandler responseHandler) {
    this.config = config;
    this.lock = lock;
    this.responseHandler = responseHandler;
    this.hummingbirdClient =
        QuarkusRestClientBuilder.newBuilder()
            .baseUri(URI.create("http://localhost"))
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build(HummingbirdClient.class);
  }

  /** Constructor for testing with a mock client. */
  HardenedImageProvider(
      HardenedImageRecommendation config,
      LockService lock,
      HardenedImageResponseHandler responseHandler,
      HummingbirdClient hummingbirdClient) {
    this.config = config;
    this.lock = lock;
    this.responseHandler = responseHandler;
    this.hummingbirdClient = hummingbirdClient;
  }

  /**
   * Periodic refresh job that fetches hardened image data from Hummingbird. Acquires a Redis
   * distributed lock before fetching to prevent concurrent refresh across production replicas.
   */
  @Scheduled(every = "{trustedcontent.recommendation.hardened.refresh-interval}", delayed = "PT0S")
  void refresh() {
    if (config.url().isEmpty() || config.url().get().isBlank()) {
      LOG.warn("Hummingbird URL not configured, hardened image provider is disabled");
      return;
    }

    String url = config.url().get();

    try {
      if (!lock.tryAcquire(LOCK_KEY, config.lockTtl())) {
        LOG.info("Lock held by another instance, skipping hardened image refresh");
        return;
      }

      LOG.info("Acquired refresh lock, fetching hardened image data from Hummingbird");
      Map<String, IndexedRecommendation> newData = fetchAndParseData(url);
      if (newData.isEmpty() && index.size() > 0) {
        LOG.warn(
            "Hummingbird returned empty data, keeping existing index with "
                + index.size()
                + " entries");
      } else {
        index.replaceAll(newData);
        LOG.infof("Hardened image index updated with %d entries", newData.size());
      }
    } catch (Exception e) {
      LOG.errorf(e, "Failed to refresh hardened image data from %s", url);
    } finally {
      try {
        lock.release(LOCK_KEY);
      } catch (Exception e) {
        LOG.warnf(e, "Failed to release refresh lock: %s", LOCK_KEY);
      }
    }
  }

  /**
   * Looks up a hardened image recommendation for the given base image reference.
   *
   * @param baseImageRef the base image reference to look up
   * @return the recommendation, or {@code null} if none is available
   */
  public IndexedRecommendation lookup(String baseImageRef) {
    return index.get(baseImageRef);
  }

  /** Returns the current index for inspection. */
  public HardenedImageIndex getIndex() {
    return index;
  }

  /**
   * Fetches the Hummingbird report and parses it into an inverted index mapping base image
   * references to hardened image recommendations.
   */
  Map<String, IndexedRecommendation> fetchAndParseData(String url) throws Exception {
    String body = hummingbirdClient.fetchReport(URI.create(url));
    return responseHandler.parseAndInvertMapping(body);
  }
}
