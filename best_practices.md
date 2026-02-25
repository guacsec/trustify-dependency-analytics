
### Pattern 1: After removing or decommissioning a feature/provider/integration, delete all related configuration, deployment wiring, and code paths (routes, aggregations, env vars, constants) to avoid dead code and misleading operational setup.

Example code before:
```
// Code path still assumes a provider exists
from("direct:scan")
  .split(exchangeProperty("providers"))
  .aggregate(constant(true), new ProviderAggregator())
  .to("bean:osvProvider");

// Deployment/config still injects unused infra vars
%prod.redis.hosts=redis://${REDIS_HOST}:${REDIS_PORT}
```

Example code after:
```
// Provider removed -> simplify route
from("direct:scan")
  .process(this::setProviders)
  .to("bean:trustifyProvider");

// Remove unused infra configuration/env vars entirely
# (deleted) %prod.redis.hosts=...
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-dependency-analytics/pull/545#discussion_r2611241285
- https://github.com/guacsec/trustify-dependency-analytics/pull/526#discussion_r2509732455
</details>


___

<b>Pattern 2: When building responses/reports from provider data, guard all nullable fields before dereferencing and structure error handling so the exception is consistently discovered/unwrapped and mapped to stable status codes/messages.
</b>

Example code before:
```
Exception ex = (Exception) exchange.getProperty("EXCEPTION_CAUGHT");
Throwable cause = ex.getCause();              // can be null
if (!item.issues().isEmpty()) {              // NPE if issues() is null
  report.addAll(item.issues());
}
```

Example code after:
```
Exception ex = firstNonNull(
  exchange.getProperty("EXCEPTION_CAUGHT", Exception.class),
  exchange.getException()
);
Exception unwrapped = unwrapRuntimeWrapper(ex);

if (item == null || item.issues() == null || item.issues().isEmpty()) {
  return;
}
report.addAll(item.issues());
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-dependency-analytics/pull/534#discussion_r2570253758
</details>


___

<b>Pattern 3: Centralize default values and branding/product-specific strings in a single configuration source (backend config mapping or frontend defaults), and render UI sections conditionally based on presence of config instead of hardcoding vendor names, icons, or text in components.
</b>

Example code before:
```
const brandingConfig = appContext.brandingConfig || {
  displayName: "Trustify",
  exploreUrl: "https://example.com",
};

<Title>Red Hat Overview of security issues</Title>
<RedhatIcon />
<CardTitle>Red Hat Remediations</CardTitle>
```

Example code after:
```
// Defaults live in one place (e.g., frontend constants or backend ConfigMapping)
const branding = getBrandingConfig(appContext.brandingConfig);

{branding.exploreTitle?.trim() && (
  <CardTitle>{branding.exploreTitle}</CardTitle>
)}

<Title>{branding.displayName} Overview of security issues</Title>
{branding.icon ? <img src={branding.icon} /> : <DefaultIcon />}
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-dependency-analytics/pull/522#discussion_r2468750000
- https://github.com/guacsec/trustify-dependency-analytics/pull/522#discussion_r2472029149
- https://github.com/guacsec/trustify-dependency-analytics/pull/522#discussion_r2472060188
- https://github.com/guacsec/trustify-dependency-analytics/pull/522#discussion_r2472030034
</details>


___

<b>Pattern 4: Cache only successful, complete results and accurately report what was cached; avoid writing placeholder/empty cache entries for misses unless explicitly intended, and ensure logging reflects actual cached count rather than requested miss count.
</b>

Example code before:
```
if (response == null || response.getStatus() == null) return;

for (Ref r : misses) {
  Item item = response.items().get(r.key());
  cache.set("items:" + r.key(), item != null ? item : Item.empty()); // caches failures/empties
}
log.debug("Cached " + misses.size() + " items");
```

Example code after:
```
if (response == null || response.getStatus() == null || !response.getStatus().ok()) return;
if (response.items() == null || misses == null || misses.isEmpty()) return;

int cached = 0;
for (var entry : response.items().entrySet()) {
  if (misses.contains(new Ref(entry.getKey()))) {
    cache.set("items:" + entry.getKey(), entry.getValue());
    cached++;
  }
}
log.debug("Cached " + cached + " items");
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-dependency-analytics/pull/552#discussion_r2631827041
</details>


___
