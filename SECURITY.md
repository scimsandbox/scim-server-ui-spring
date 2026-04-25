# Security Policy

## Supported Versions

Security fixes are applied to:

- the current `main` branch
- the latest tagged release built from this repository

Older commits and local forks should not be assumed to receive backported
security fixes.

## Reporting a Vulnerability

Do not open public GitHub issues for security reports.

Use GitHub Security Advisories for private disclosure:

1. Open the repository Security tab.
2. Open Advisories.
3. Create a draft security advisory.
4. Include the affected route, class, workflow, or build path, along with reproduction steps,
   impact, and any mitigation you have identified.

If private reporting is unavailable, use the maintainer contact options listed
on GitHub.

## Scope of Security Review

This repository is the management UI and management API for the SCIM sandbox.
The highest-risk areas are:

- Auth0 OIDC login and role mapping in `SecurityConfig` and the shared security
  helpers
- workspace access control for `/api/workspaces/**`
- bearer-token generation, hashing, listing, and revocation for workspaces
- direct writes to shared SCIM user, group, membership, and log tables
- request log storage and display, because payloads may contain sensitive data
- actuator exposure, which is protected separately with `X-API-KEY`

This repo does not serve the SCIM provider endpoints itself, but it manages data
and tokens that are used by the separate SCIM server. Secure that service and
its deployment independently as well.

## Current Controls

The codebase currently includes these baseline controls:

- interactive login via Spring Security OAuth2 client and Auth0 OIDC
- role mapping from a configurable OIDC claim to `ROLE_ADMIN` and `ROLE_USER`
- CSRF protection for the web UI and management API
- actuator protection with a required `X-API-KEY` header
- constant-time comparison for actuator API-key validation
- SHA-256 hashing for workspace tokens before persistence
- token revocation support
- per-workspace access checks before reading or mutating data

## Operational Guidance

If you deploy this app anywhere beyond a private sandbox, do all of the
following first:

1. Replace all Auth0 settings, datasource credentials, and actuator keys with
   environment-specific secrets.
2. Put the UI behind HTTPS and a trusted reverse proxy.
3. Limit access to authenticated operators only. This is an admin surface, not
   a public application.
4. Protect `/actuator/**` separately and rotate the actuator API key when staff
   or environments change.
5. Treat workspace bearer tokens as secrets. They are shown once and stored only
   as hashes.
6. Review whether request logs may store personal data, credentials, or tenant
   payloads before enabling the app in any non-test environment.
7. Use least-privileged database credentials and separate databases or schemas
   per environment.

## Secrets Handling

- Do not commit Auth0 secrets, database passwords, actuator keys, or raw
  workspace tokens.
- Do not reuse local sandbox values in shared or production environments.
- Assume any example values in documentation are placeholders only.

## Security Testing Expectations

When changing authentication, authorization, token handling, logging, or direct
data access, validate at least the relevant combination of:

- the affected unit tests under `src/test/java`
- the relevant integration tests using Testcontainers PostgreSQL
- the changed UI/API flow manually in a local environment

If your change affects the shared schema or token behavior, also verify it
against the separate SCIM server that uses the same tables.