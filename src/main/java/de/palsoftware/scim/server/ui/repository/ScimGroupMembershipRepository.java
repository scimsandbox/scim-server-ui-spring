package de.palsoftware.scim.server.ui.repository;

import de.palsoftware.scim.server.ui.model.ScimGroupMembership;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface ScimGroupMembershipRepository extends JpaRepository<ScimGroupMembership, UUID> {

    @Modifying
    @Query("delete from ScimGroupMembership membership where membership.workspaceId = :workspaceId and membership.memberValue = :memberValue")
    long deleteByWorkspaceIdAndMemberValue(@Param("workspaceId") UUID workspaceId, @Param("memberValue") UUID memberValue);

    @Modifying
    @Query("delete from ScimGroupMembership membership where membership.workspaceId = :workspaceId and membership.memberValue in :memberValues")
    long deleteByWorkspaceIdAndMemberValueIn(@Param("workspaceId") UUID workspaceId, @Param("memberValues") List<UUID> memberValues);

    @Modifying
    @Query("delete from ScimGroupMembership membership where membership.workspaceId = :workspaceId and membership.group.id = :groupId")
    long deleteByWorkspaceIdAndGroupId(@Param("workspaceId") UUID workspaceId, @Param("groupId") UUID groupId);

    @Modifying
    @Query("delete from ScimGroupMembership membership where membership.workspaceId = :workspaceId and membership.group.id in :groupIds")
    long deleteByWorkspaceIdAndGroupIdIn(@Param("workspaceId") UUID workspaceId, @Param("groupIds") List<UUID> groupIds);
}
