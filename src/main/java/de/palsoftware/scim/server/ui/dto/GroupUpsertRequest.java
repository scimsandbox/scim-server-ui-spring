package de.palsoftware.scim.server.ui.dto;

import java.util.List;

public record GroupUpsertRequest(
        String displayName,
        String externalId, 
        List<Member> members) {
    public record Member(
            String value,
            String type, String display) {
    }
}
