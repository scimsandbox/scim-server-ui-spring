cat src/main/java/de/palsoftware/scim/server/ui/repository/WorkspaceStatsRepository.java | sed -e "s/(SELECT COUNT(\*) FROM scim_users) AS total_users,/(SELECT NULLIF(reltuples::bigint, 0) FROM pg_class WHERE relname = 'scim_users') AS total_users,/" \
-e "s/(SELECT COUNT(\*) FROM scim_groups) AS total_groups,/(SELECT NULLIF(reltuples::bigint, 0) FROM pg_class WHERE relname = 'scim_groups') AS total_groups,/" \
-e "s/(SELECT COUNT(\*) FROM workspace_tokens) AS total_tokens,/(SELECT NULLIF(reltuples::bigint, 0) FROM pg_class WHERE relname = 'workspace_tokens') AS total_tokens,/" \
-e "s/(SELECT COUNT(\*) FROM scim_request_logs) AS total_logs,/(SELECT NULLIF(reltuples::bigint, 0) FROM pg_class WHERE relname = 'scim_request_logs') AS total_logs,/" \
-e "s/(SELECT COUNT(\*) FROM scim_group_memberships) AS total_group_memberships/(SELECT NULLIF(reltuples::bigint, 0) FROM pg_class WHERE relname = 'scim_group_memberships') AS total_group_memberships/" \
-e "s/.*AS total_emails,//" \
-e "s/.*AS total_phone_numbers,//" \
-e "s/.*AS total_addresses,//" \
-e "s/.*AS total_entitlements,//" \
-e "s/.*AS total_roles,//" \
-e "s/.*AS total_ims,//" \
-e "s/.*AS total_photos,//" \
-e "s/.*AS total_x509_certificates,//" > WorkspaceStatsRepository.java.new
mv WorkspaceStatsRepository.java.new src/main/java/de/palsoftware/scim/server/ui/repository/WorkspaceStatsRepository.java
