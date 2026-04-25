package de.palsoftware.scim.server.ui.repository;

public record WorkspaceDataStats(
        long userCount,
        long groupCount,
        long tokenCount,
        long logCount,
        long emailCount,
        long phoneNumberCount,
        long addressCount,
        long entitlementCount,
        long roleCount,
        long imCount,
        long photoCount,
        long x509CertificateCount,
        long groupMembershipCount,
        long estimatedRowBytes) {

    public long userAttributeObjectCount() {
        return emailCount
                + phoneNumberCount
                + addressCount
                + entitlementCount
                + roleCount
                + imCount
                + photoCount
                + x509CertificateCount;
    }

    public long objectCount() {
        return userCount
                + groupCount
                + tokenCount
                + logCount
                + userAttributeObjectCount();
    }

    public long relationCount() {
        return groupMembershipCount;
    }

    public long storedRowCount() {
        return objectCount() + relationCount();
    }
}