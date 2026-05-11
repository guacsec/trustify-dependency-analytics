# Suggested Commands

## Build & Verify
- `mvn spotless:apply` — Auto-format all Java sources (Google Java Format)
- `mvn test` — Run unit tests
- `mvn verify` — Run all tests including integration tests
- `mvn compile` — Compile (also builds UI if ui/ changed)
- `mvn clean install` — Full build

## UI (in ui/ directory)
- `yarn install` — Install dependencies
- `yarn build` — Build React app (output goes to freemarker/templates/generated/)
- `yarn lint` / `yarn lint:fix` — ESLint + Prettier checks

## Pre-Commit Checklist
1. `mvn spotless:apply`
2. If ui/ changed: `cd ui && yarn lint && yarn build`
3. `mvn verify`

## Development
- `mvn quarkus:dev` — Run in dev mode
- Dev profile: `%dev.quarkus.log.level=DEBUG`

## System Utilities (macOS / Darwin)
- `git`, `ls`, `find`, `grep` — Standard Unix commands
- `mvn` — Maven wrapper or system Maven
