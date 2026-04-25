package de.palsoftware.scim.server.ui.repository;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public class WorkspaceStatsRepository {

    private static final String WORKSPACE_STATS_SQL = """
            WITH counts AS (
                SELECT
                    (SELECT COUNT(*) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_users,
                    (SELECT COUNT(*) FROM scim_users) AS total_users,
                    (SELECT COUNT(*) FROM scim_groups g WHERE g.workspace_id = :workspaceId) AS workspace_groups,
                    (SELECT COUNT(*) FROM scim_groups) AS total_groups,
                    (SELECT COUNT(*) FROM workspace_tokens t WHERE t.workspace_id = :workspaceId) AS workspace_tokens,
                    (SELECT COUNT(*) FROM workspace_tokens) AS total_tokens,
                    (SELECT COUNT(*) FROM scim_request_logs l WHERE l.workspace_id = :workspaceId) AS workspace_logs,
                    (SELECT COUNT(*) FROM scim_request_logs) AS total_logs,
                    (SELECT COALESCE(SUM(json_array_length(emails)), 0) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_emails,
                    (SELECT COALESCE(SUM(json_array_length(emails)), 0) FROM scim_users) AS total_emails,
                    (SELECT COALESCE(SUM(json_array_length(phone_numbers)), 0) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_phone_numbers,
                    (SELECT COALESCE(SUM(json_array_length(phone_numbers)), 0) FROM scim_users) AS total_phone_numbers,
                    (SELECT COALESCE(SUM(json_array_length(addresses)), 0) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_addresses,
                    (SELECT COALESCE(SUM(json_array_length(addresses)), 0) FROM scim_users) AS total_addresses,
                    (SELECT COALESCE(SUM(json_array_length(entitlements)), 0) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_entitlements,
                    (SELECT COALESCE(SUM(json_array_length(entitlements)), 0) FROM scim_users) AS total_entitlements,
                    (SELECT COALESCE(SUM(json_array_length(roles)), 0) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_roles,
                    (SELECT COALESCE(SUM(json_array_length(roles)), 0) FROM scim_users) AS total_roles,
                    (SELECT COALESCE(SUM(json_array_length(ims)), 0) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_ims,
                    (SELECT COALESCE(SUM(json_array_length(ims)), 0) FROM scim_users) AS total_ims,
                    (SELECT COALESCE(SUM(json_array_length(photos)), 0) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_photos,
                    (SELECT COALESCE(SUM(json_array_length(photos)), 0) FROM scim_users) AS total_photos,
                    (SELECT COALESCE(SUM(json_array_length(x509_certificates)), 0) FROM scim_users u WHERE u.workspace_id = :workspaceId) AS workspace_x509_certificates,
                    (SELECT COALESCE(SUM(json_array_length(x509_certificates)), 0) FROM scim_users) AS total_x509_certificates,
                    (SELECT COUNT(*) FROM scim_group_memberships m WHERE m.workspace_id = :workspaceId) AS workspace_group_memberships,
                    (SELECT COUNT(*) FROM scim_group_memberships) AS total_group_memberships
            )
            SELECT
                workspace_users,
                workspace_groups,
                workspace_tokens,
                workspace_logs,
                workspace_emails,
                workspace_phone_numbers,
                workspace_addresses,
                workspace_entitlements,
                workspace_roles,
                workspace_ims,
                workspace_photos,
                workspace_x509_certificates,
                workspace_group_memberships,
                (
                    COALESCE(pg_total_relation_size('scim_users'::regclass)::numeric * workspace_users / NULLIF(total_users, 0), 0)
                    + COALESCE(pg_total_relation_size('scim_groups'::regclass)::numeric * workspace_groups / NULLIF(total_groups, 0), 0)
                    + COALESCE(pg_total_relation_size('workspace_tokens'::regclass)::numeric * workspace_tokens / NULLIF(total_tokens, 0), 0)
                    + COALESCE(pg_total_relation_size('scim_request_logs'::regclass)::numeric * workspace_logs / NULLIF(total_logs, 0), 0)
                    + COALESCE(pg_total_relation_size('scim_group_memberships'::regclass)::numeric * workspace_group_memberships / NULLIF(total_group_memberships, 0), 0)
                )::bigint
            FROM counts
            """;

    private final EntityManager entityManager;

    public WorkspaceStatsRepository(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    public WorkspaceDataStats fetchWorkspaceDataStats(UUID workspaceId) {
        Object[] row = (Object[]) entityManager.createNativeQuery(WORKSPACE_STATS_SQL)
                .setParameter("workspaceId", workspaceId)
                .getSingleResult();

        return new WorkspaceDataStats(
                toLong(row[0]),
                toLong(row[1]),
                toLong(row[2]),
                toLong(row[3]),
                toLong(row[4]),
                toLong(row[5]),
                toLong(row[6]),
                toLong(row[7]),
                toLong(row[8]),
                toLong(row[9]),
                toLong(row[10]),
                toLong(row[11]),
                toLong(row[12]),
                toLong(row[13]));
    }

    private long toLong(Object value) {
        return value == null ? 0L : ((Number) value).longValue();
    }
}