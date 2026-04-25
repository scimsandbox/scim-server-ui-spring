# Contributing

Thanks for contributing to scim-server-ui.

This repository is the management UI and API for the SCIM sandbox. Keep changes
focused on the web app, its security model, workspace and token management,
SCIM data administration, and documentation that matches the live repository
structure.

## Ground Rules

- Keep each change narrow and intentional.
- Do not mix unrelated refactors into UI, workflow, or documentation changes.
- Do not commit bearer tokens, database credentials, Auth0 secrets, or
  machine-specific Maven settings.
- Update docs when runtime setup, dependency resolution, or security behavior
  changes.

## Before You Start

1. Check for existing issues or pull requests that already cover the same work.
2. Read [README.md](./README.md) before changing runtime behavior or setup.
3. If database expectations change, update the docs with the matching
   `scim-server-db` assumptions.

## Local Setup

### Prerequisites

- JDK 25
- Maven 3.9+
- PostgreSQL
- an Auth0 application for interactive login testing
- Docker if you want to build the container image locally

### Required runtime configuration

At minimum, set:

- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`
- `ACTUATOR_API_KEY`
- `AUTH0_CLIENT_ID`
- `AUTH0_CLIENT_SECRET`
- `AUTH0_ISSUER_URI`
- `AUTH0_REDIRECT_URI`

Optional but commonly useful:

- `SERVER_PORT`
- `APP_SCIM_API_BASE_URL`
- `APP_SECURITY_OIDC_ROLE_CLAIM`
- `APP_SECURITY_OIDC_ADMIN_ROLE`
- `APP_SECURITY_OIDC_USER_ROLE`

### Database expectation

This repo validates an existing schema on startup. It does not create tables.

Before running locally, apply the migrations from `scim-server-db` so the
database already contains the shared SCIM tables and management tables this
app expects.

## Validation

Validate changes before opening a PR.

Common checks:

```bash
mvn clean verify
```

## Code Areas

The main implementation areas are:

- `src/main/java/de/palsoftware/scim/server/ui/controller`: UI and REST
  endpoints
- `src/main/java/de/palsoftware/scim/server/ui/service`: workspace, token,
  user, group, log, and sample-data logic
- `src/main/java/de/palsoftware/scim/server/ui/security`: OIDC login, CSRF,
  logout, and actuator protection
- `src/main/java/de/palsoftware/scim/server/ui/model` and `repository`: JPA
  entities and data access
- `src/main/resources/templates` and `src/main/resources/static`: Thymeleaf UI,
  CSS, JavaScript, and assets

## Project Conventions

Follow the existing patterns unless a refactor is explicitly part of the work:

- no Lombok
- prefer constructor injection
- DTOs may use Java records
- keep transactional boundaries deliberate
- management pagination is 1-based and capped at 200 results
- use the existing response mappers instead of building ad hoc JSON inline
- preserve workspace-scoped access rules; do not introduce tenant-agnostic data
  access

## If You Change These Areas

### Authentication or authorization

Review and update as needed:

- `SecurityConfig`
- `AuthenticatedUser`
- shared helpers under `src/main/java/de/palsoftware/scim/server/ui/security`
- `README.md` and `SECURITY.md`

### User or group management behavior

Review and update as needed:

- DTOs in `src/main/java/de/palsoftware/scim/server/ui/dto`
- `ScimAdminService`
- response mappers in `src/main/java/de/palsoftware/scim/server/ui/utils`
- the relevant controller endpoints
- the corresponding UI forms and JavaScript
- tests covering the changed behavior

### Workspace or token behavior

Review and update as needed:

- `WorkspaceService`
- `ApiWorkspacesController`
- workspace response mappers
- any documentation that mentions setup, tokens, or stats

### Docker or CI

Review and update as needed:

- `Dockerfile`
- the GitHub workflows
- `README.md`

## Pull Request Checklist

Before opening a PR, make sure it:

- explains what changed and why
- keeps unrelated edits out of scope
- updates docs if setup, security, or dependency expectations changed
- runs the relevant validation steps
- does not include secrets or machine-specific noise

## Reporting Bugs

When reporting a problem, include:

- whether the issue is in the UI, security flow, persistence layer, or API
- the relevant route or class
- the database state or migration version if relevant
- the relevant Maven or runtime configuration with secrets removed
- reproduction steps, observed behavior, and any stack trace

## Security Issues

Do not report vulnerabilities through public issues.

Follow [SECURITY.md](./SECURITY.md) instead.