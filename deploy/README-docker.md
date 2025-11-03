# Trustify Docker Compose Deployment

This directory contains Docker Compose files for local development deployment of Trustify with its required infrastructure components.

## Files

- `docker-compose.infrastructure.yml` - Infrastructure services (Redis, PostgreSQL)
- `docker-compose.infra-sso.yml` - Infrastructure services (Keycloak)
- `docker-compose.application.yml` - Application service (trust-da)
- `env.example` - Environment variables template

## Quick Start

### 1. Start Infrastructure Services

```bash
# Start Redis, PostgreSQL, and Keycloak
docker-compose -f docker-compose.infrastructure.yml up -d

# Start Keycloak
docker-compose -f docker-compose.infra-sso.yml up -d

# Check if services are healthy
docker-compose -f docker-compose.infrastructure.yml ps
```

### 2. Configure Environment (Optional)

```bash
# Copy environment template
cp env.example .env

# Edit .env with your actual values
nano .env
```

### 3. Start Application

```bash
# Start the trust-da application
docker-compose -f docker-compose.application.yml up -d

# Check application status
docker-compose -f docker-compose.application.yml ps
```

## Services

### Infrastructure Services

| Service | Port | Description |
|---------|------|-------------|
| Redis | 6379 | Cache and session storage |
| PostgreSQL | 5432 | Database for Keycloak and application |
| Keycloak | 8080 | Identity and access management |

### Application Services

| Service | Port | Description |
|---------|------|-------------|
| trust-da | 8081 | Main application (mapped from 8080) |
| trust-da | 9001 | Management/health endpoints (mapped from 9000) |

## Access Points

- **Application**: http://localhost:8081
- **Keycloak Admin**: http://localhost:8080
  - Username: `admin`
  - Password: `admin123`
- **PostgreSQL**: localhost:5432
  - Database: `trustify`
  - Username: `trustify`
  - Password: `trustify123`
- **Redis**: localhost:6379
  - Password: `trustify123`

## Health Checks

All services include health checks. You can monitor them with:

```bash
# Check infrastructure health
docker-compose -f docker-compose.infrastructure.yml ps

# Check Keycloak health
docker-compose -f docker-compose.infra-sso.yml ps

# Check application health
docker-compose -f docker-compose.application.yml ps
```

## Logs

```bash
# View infrastructure logs
docker-compose -f docker-compose.infrastructure.yml logs -f

# View Keycloak logs
docker-compose -f docker-compose.infra-sso.yml logs -f

# View application logs
docker-compose -f docker-compose.application.yml logs -f

# View specific service logs
docker-compose -f docker-compose.application.yml logs -f trust-da
```

## Stopping Services

```bash
# Stop application
docker-compose -f docker-compose.application.yml down
# Stop Keycloak
docker-compose -f docker-compose.infa-sso.yml down
# Stop infrastructure
docker-compose -f docker-compose.infrastructure.yml down

# Stop everything and remove volumes
docker-compose -f docker-compose.infrastructure.yml down -v
docker-compose -f docker-compose.infra-sso.yml down
docker-compose -f docker-compose.application.yml down
```

## Data Persistence

- **PostgreSQL data**: Stored in Docker volume `postgres_data`
- **Redis data**: Stored in Docker volume `redis_data`

To reset all data:

```bash
docker-compose -f docker-compose.infrastructure.yml down -v
```

## Environment Variables

Create a `.env` file based on `env.example` to customize:

- `TRUSTIFY_CLIENT_ID`: Your Trustify client ID
- `TRUSTIFY_CLIENT_SECRET`: Your Trustify client secret
- `SENTRY_DSN`: Sentry DSN for error tracking
- `TELEMETRY_WRITE_KEY`: Telemetry write key

## Troubleshooting

### Services not starting

```bash
# Check logs for errors
docker-compose -f docker-compose.infrastructure.yml logs
docker-compose -f docker-compose.application.yml logs

# Restart services
docker-compose -f docker-compose.infrastructure.yml restart
docker-compose -f docker-compose.application.yml restart
```

### Port conflicts

If you have port conflicts, modify the port mappings in the compose files:

```yaml
ports:
  - "8082:8080"  # Change 8081 to 8082
```

### Network issues

The application uses an external network. If you encounter network issues:

```bash
# Create the network manually
docker network create trustify-network
```
