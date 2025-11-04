# Trustify Docker Compose Deployment

This directory contains Docker Compose files for local development deployment of Trustify with its required infrastructure components.

**Note**: Replace `docker-compose` with `podman-compose` if you're using Podman instead.

## Files

- `docker-compose.infrastructure.yml` - Infrastructure services (Redis, PostgreSQL)
- `docker-compose.application.yml` - Application service (trust-da)
- `env.example` - Environment variables template

## Quick Start

### 1. Start Infrastructure Services

```bash
# Start Redis, PostgreSQL, and Keycloak
docker-compose -f docker-compose.infrastructure.yml up -d

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

### 3. Create Network

```bash
docker network create trustify-network
```

### 4. Start Application

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

### Application Services

| Service | Port | Description |
|---------|------|-------------|
| trust-da | 8081 | Main application (mapped from 8080) |
| trust-da | 9001 | Management/health endpoints (mapped from 9000) |

## Access Points

- **Application**: http://localhost:8081
- **PostgreSQL**: localhost:5432
  - Database: `trustify`
  - Username: `trustify`
  - Password: `trustify123`
- **Redis**: localhost:6379
  - No authentication required

## Health Checks

All services include health checks. You can monitor them with:

```bash
# Check infrastructure health
docker-compose -f docker-compose.infrastructure.yml ps

# Check application health
docker-compose -f docker-compose.application.yml ps
```

## Logs

```bash
# View infrastructure logs
docker-compose -f docker-compose.infrastructure.yml logs -f

# View application logs
docker-compose -f docker-compose.application.yml logs -f

# View specific service logs
docker-compose -f docker-compose.application.yml logs -f trust-da
```

## Stopping Services

```bash
# Stop application
docker-compose -f docker-compose.application.yml down
# Stop infrastructure
docker-compose -f docker-compose.infrastructure.yml down

# Stop everything and remove volumes
docker-compose -f docker-compose.infrastructure.yml down -v
docker-compose -f docker-compose.application.yml down
```

## Data Persistence

- **PostgreSQL data**: Stored in Docker volume `postgres_data`
- **Redis data**: Stored in Docker volume `redis_data`

To reset all data:

```bash
docker-compose -f docker-compose.infrastructure.yml down -v
```

## Remove the network

```bash
docker network rm trustify-network
```

## Environment Variables

Create a `.env` file based on `env.example` to customize:

- `TRUSTIFY_HOST`: Your Trustify server host
- `TRUSTIFY_CLIENT_ID`: Your Trustify client ID
- `TRUSTIFY_CLIENT_SECRET`: Your Trustify client secret
- `TRUSTIFY_AUTH_SERVER_URL`: The Trustify SSO Server URL
- `SENTRY_DSN`: Sentry DSN for error tracking (Optional)
- `TELEMETRY_WRITE_KEY`: Telemetry write key (Optional)

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
