# SCIM Sandbox - Server UI Spring

This repository contains the Spring Boot management UI and management API for
the SCIM sandbox.

## What This Repo Contains

- a server-side rendered Thymeleaf UI for browsing and managing workspaces
- a REST API under `/api/**` for workspaces, tokens, users, groups, logs, and
  sample data generation
- shared SCIM JPA entities, repositories, and security helpers under
  `de.palsoftware.scim.server.common.*`
- Auth0 OIDC login, role mapping, CSRF protection, and an actuator API-key
  filter
- a Dockerfile for packaging the application as a container image

## What This Repo Does Not Contain

- the SCIM provider endpoints such as `/ws/{workspaceId}/scim/v2/**`
- the validator suite or validator management UI
- Docker Compose, Kubernetes manifests, or the old multi-service reactor layout
- database migrations for the shared SCIM schema

This application manages the shared sandbox data directly through JPA. It does
not proxy requests to a SCIM API. The `APP_SCIM_API_BASE_URL` setting is used
only to display the external SCIM base URL in the UI.

## Features

- create, list, inspect, and delete workspaces
- calculate per-workspace object counts and estimated storage usage
- create, list, and revoke workspace bearer tokens (with configurable expiration)
- create, edit, search, and delete SCIM users and groups
- inspect and clear request logs stored for a workspace
- generate sample users, groups, and memberships
- show the currently configured external SCIM base URL for each workspace
- protect `/actuator/**` with an `X-API-KEY` header

## Routes

| Area | Routes |
| --- | --- |
| UI | `/`, `/workspaces/{workspaceId}` |
| Workspaces | `GET/POST /api/workspaces`, `GET/DELETE /api/workspaces/{workspaceId}`, `GET /api/workspaces/{workspaceId}/stats` |
| Tokens | `GET/POST /api/workspaces/{workspaceId}/tokens`, `DELETE /api/workspaces/{workspaceId}/tokens/{tokenId}` |
| Users | `GET/POST /api/workspaces/{workspaceId}/users`, `PUT/DELETE /api/workspaces/{workspaceId}/users/{userId}`, `GET /api/workspaces/{workspaceId}/users/lookup` |
| Groups | `GET/POST /api/workspaces/{workspaceId}/groups`, `PUT/DELETE /api/workspaces/{workspaceId}/groups/{groupId}`, `GET /api/workspaces/{workspaceId}/groups/lookup` |
| Logs | `GET/DELETE /api/workspaces/{workspaceId}/logs` |
| Sample data | `POST /api/workspaces/{workspaceId}/generate/{users|groups|relations|all}` |
| Actuator | `GET /actuator/health` with `X-API-KEY` |

## Repository Layout

```text
.
├── Dockerfile
├── pom.xml
└── src
    ├── main
    │   ├── java
    │   │   └── de/palsoftware/scim/server/ui
    │   │       ├── controller
    │   │       ├── dto
    │   │       ├── model
    │   │       ├── repository
    │   │       ├── security
    │   │       ├── service
    │   │       └── utils
    │   └── resources
    │       ├── application.yml
    │       ├── static
    │       └── templates
    └── test
        └── java
            └── de/palsoftware/scim/server/ui
```

## Runtime Notes

- Java: 25
- Spring Boot: 3.5.14
- Database: PostgreSQL
- Templating: Thymeleaf
- Security: Spring Security OAuth2 client with Auth0 OIDC
- Persistence: Spring Data JPA

The application uses `spring.jpa.hibernate.ddl-auto=validate`, so it expects an
existing schema. It will not create tables for you on startup.

## Configuration

The application relies on standard Spring Boot datasource configuration plus a
small set of app-specific settings.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SPRING_DATASOURCE_URL` | yes | PostgreSQL JDBC URL |
| `SPRING_DATASOURCE_USERNAME` | yes | PostgreSQL username |
| `SPRING_DATASOURCE_PASSWORD` | yes | PostgreSQL password |
| `ACTUATOR_API_KEY` | yes | Required by the `/actuator/**` API-key filter |
| `AUTH0_CLIENT_ID` | yes | Auth0 OIDC client ID |
| `AUTH0_CLIENT_SECRET` | yes | Auth0 OIDC client secret |
| `AUTH0_ISSUER_URI` | yes | Auth0 issuer URI |
| `AUTH0_REDIRECT_URI` | yes | OAuth redirect URI used by Spring Security |
| `APP_SCIM_API_BASE_URL` | no | External SCIM API base URL shown in the UI. Default: `http://localhost:8080` |
| `APP_TOKEN_DEFAULT_VALIDITY` | no | ISO-8601 duration for new token lifetime. Default: `P30D` (30 days) |
| `APP_SECURITY_OIDC_ROLE_CLAIM` | no | Claim used to extract roles. Default: `https://scimplayground.dev/roles` |
| `APP_SECURITY_OIDC_ADMIN_ROLE` | no | Role value mapped to `ROLE_ADMIN`. Default: `admin` |
| `APP_SECURITY_OIDC_USER_ROLE` | no | Role value mapped to `ROLE_USER`. Default: `user` |
| `SERVER_PORT` | no | Spring Boot server port. Default: `8080` |

## Running Locally

### 1. Prepare a PostgreSQL schema

This repo does not include the migrations that create the shared SCIM tables.
Before starting the app, make sure the database already contains the schema used
by the SCIM sandbox, including the management tables such as `mgmt_users`.

### 2. Export configuration

```bash
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/scim
export SPRING_DATASOURCE_USERNAME=scim
export SPRING_DATASOURCE_PASSWORD=scim
export ACTUATOR_API_KEY=change-me
export AUTH0_CLIENT_ID=your-auth0-client-id
export AUTH0_CLIENT_SECRET=your-auth0-client-secret
export AUTH0_ISSUER_URI=https://your-tenant.us.auth0.com/
export AUTH0_REDIRECT_URI=http://localhost:8080/login/oauth2/code/auth0
export APP_SCIM_API_BASE_URL=http://localhost:8080
```

If you want the UI on `8081`, also set:

```bash
export SERVER_PORT=8081
export AUTH0_REDIRECT_URI=http://localhost:8081/login/oauth2/code/auth0
```

### 3. Start the app

```bash
mvn spring-boot:run
```

By default, Spring Boot listens on `http://localhost:8080` unless you set
`SERVER_PORT`.

### 4. Check health

```bash
curl -H 'X-API-KEY: change-me' http://localhost:8080/actuator/health
```

Adjust the port if you set `SERVER_PORT`.

## Building

```bash
mvn clean package
```

The packaged JAR is written to `target/`.

## Docker

Build the image:

```bash
docker build -t scim-server-ui .
```

Run it on `8081` so the container port matches the Dockerfile metadata:

```bash
docker run --rm \
  -p 8081:8081 \
  -e SERVER_PORT=8081 \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://host.docker.internal:5432/scim \
  -e SPRING_DATASOURCE_USERNAME=scim \
  -e SPRING_DATASOURCE_PASSWORD=scim \
  -e ACTUATOR_API_KEY=change-me \
  -e AUTH0_CLIENT_ID=your-auth0-client-id \
  -e AUTH0_CLIENT_SECRET=your-auth0-client-secret \
  -e AUTH0_ISSUER_URI=https://your-tenant.us.auth0.com/ \
  -e AUTH0_REDIRECT_URI=http://localhost:8081/login/oauth2/code/auth0 \
  scim-server-ui
```

## Testing

```bash
mvn clean verify
```

All tests are self-contained. Unit tests use plain JUnit. Integration tests use
Testcontainers PostgreSQL with schema created via `spring.jpa.hibernate.ddl-auto`.

## Versioning

The working version lives in `pom.xml`. The manual release workflow runs from
`main`, uses the Maven Release Plugin to publish the current `-SNAPSHOT`
version as `vX.Y.Z`, and creates the GitHub release. Publishing that GitHub
release triggers the Docker publish workflow for `edipal/scim-server-ui-spring`.

## Token Expiration

Every newly created workspace token receives an `expires_at` timestamp computed
as `now + app.token.default-validity`. The default validity is **30 days**
(`P30D`). Override it at runtime with the `APP_TOKEN_DEFAULT_VALIDITY`
environment variable using any ISO-8601 duration (e.g. `P7D` for one week,
`P90D` for 90 days).

The SCIM API server (`scim-server-impl-spring`) enforces expiration at request
time: any request carrying an expired token receives a `401 Unauthorized`
response with the detail `"Token has expired"`. Legacy tokens that have a
`NULL` `expires_at` value in the database are treated as non-expiring and
continue to work.

The token lookup cache in `scim-server-impl-spring` (Caffeine,
`expireAfterWrite=60s`) does not interfere with expiration enforcement because
the expiry check runs against the cached entity's `expiresAt` field on every
request, not against the cache TTL.

## Development Notes

- `SecurityConfig` configures Auth0 login, role mapping, logout, and CSRF
- `WorkspaceService` owns workspace access control, token generation, and stats
- `ScimAdminService` performs direct CRUD on shared SCIM tables for users and
  groups
- `DataGeneratorService` creates sample data for the UI
- `UiController` renders the Thymeleaf pages and injects the external SCIM base
  URL into the workspace page

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

See [SECURITY.md](./SECURITY.md).

## License

This project is licensed under the Apache License, Version 2.0. See `LICENSE`.