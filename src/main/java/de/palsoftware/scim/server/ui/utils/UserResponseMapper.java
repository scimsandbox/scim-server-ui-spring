package de.palsoftware.scim.server.ui.utils;

import de.palsoftware.scim.server.ui.model.ScimUser;
import de.palsoftware.scim.server.ui.model.ScimUserAddress;
import de.palsoftware.scim.server.ui.model.ScimUserEmail;
import de.palsoftware.scim.server.ui.model.ScimUserEntitlement;
import de.palsoftware.scim.server.ui.model.ScimUserIm;
import de.palsoftware.scim.server.ui.model.ScimUserPhoneNumber;
import de.palsoftware.scim.server.ui.model.ScimUserPhoto;
import de.palsoftware.scim.server.ui.model.ScimUserRole;
import de.palsoftware.scim.server.ui.model.ScimUserX509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class UserResponseMapper {

    private UserResponseMapper() {}

    private static final String KEY_USER_NAME = "userName";
    private static final String KEY_DISPLAY_NAME = "displayName";
    private static final String KEY_EXTERNAL_ID = "externalId";
    private static final String KEY_NAME = "name";
    private static final String KEY_VALUE = "value";
    private static final String KEY_TYPE = "type";
    private static final String KEY_DISPLAY = "display";
    private static final String KEY_CREATED_AT = "createdAt";
    private static final String KEY_LAST_MODIFIED = "lastModified";

    public static Map<String, Object> userToMap(ScimUser user) {
        Map<String, Object> map = new LinkedHashMap<>(22, 1.0f);
        map.put("id", user.getId().toString());
        map.put(KEY_USER_NAME, user.getUserName());
        map.put(KEY_DISPLAY_NAME, user.getDisplayName());
        map.put(KEY_EXTERNAL_ID, user.getExternalId());
        map.put(KEY_NAME, userNameToMap(user));
        map.put("nickName", user.getNickName());
        map.put("profileUrl", user.getProfileUrl());
        map.put("title", user.getTitle());
        map.put("userType", user.getUserType());
        map.put("preferredLanguage", user.getPreferredLanguage());
        map.put("locale", user.getLocale());
        map.put("timezone", user.getTimezone());
        map.put("enterprise", enterpriseToMap(user));
        map.put("emails", emailListToMap(safeList(user.getEmails())));
        map.put("phoneNumbers", phoneListToMap(safeList(user.getPhoneNumbers())));
        map.put("addresses", addressListToMap(safeList(user.getAddresses())));
        map.put("entitlements", entitlementListToMap(safeList(user.getEntitlements())));
        map.put("roles", roleListToMap(safeList(user.getRoles())));
        map.put("ims", imListToMap(safeList(user.getIms())));
        map.put("photos", photoListToMap(safeList(user.getPhotos())));
        map.put("x509Certificates", certificateListToMap(safeList(user.getX509Certificates())));
        map.put("active", user.isActive());
        map.put(KEY_CREATED_AT, user.getCreatedAt() != null ? user.getCreatedAt().toString() : null);
        map.put(KEY_LAST_MODIFIED, user.getLastModified() != null ? user.getLastModified().toString() : null);
        map.put("meta", metaToMap(user.getCreatedAt(), user.getLastModified(), user.getVersion()));
        return map;
    }

    public static Map<String, Object> userLookupToMap(ScimUser user) {
        Map<String, Object> map = new LinkedHashMap<>(3, 1.0f);
        map.put("id", user.getId().toString());
        map.put(KEY_USER_NAME, user.getUserName());
        map.put(KEY_DISPLAY_NAME, user.getDisplayName());
        return map;
    }

    private static List<Map<String, Object>> emailListToMap(List<ScimUserEmail> emails) {
        List<Map<String, Object>> emailList = new ArrayList<>(emails.size());
        for (ScimUserEmail email : emails) {
            emailList.add(multiValueToMap(email.getValue(), email.getType(), email.getDisplay(), email.isPrimaryFlag()));
        }
        return emailList;
    }

    private static List<Map<String, Object>> phoneListToMap(List<ScimUserPhoneNumber> phoneNumbers) {
        List<Map<String, Object>> phoneList = new ArrayList<>(phoneNumbers.size());
        for (ScimUserPhoneNumber phone : phoneNumbers) {
            phoneList.add(multiValueToMap(phone.getValue(), phone.getType(), phone.getDisplay(), phone.isPrimaryFlag()));
        }
        return phoneList;
    }

    private static List<Map<String, Object>> addressListToMap(List<ScimUserAddress> addresses) {
        List<Map<String, Object>> addressList = new ArrayList<>(addresses.size());
        for (ScimUserAddress address : addresses) {
            addressList.add(addressToMap(address));
        }
        return addressList;
    }

    private static List<Map<String, Object>> entitlementListToMap(List<ScimUserEntitlement> entitlements) {
        List<Map<String, Object>> entitlementList = new ArrayList<>(entitlements.size());
        for (ScimUserEntitlement entitlement : entitlements) {
            entitlementList.add(multiValueToMap(
                    entitlement.getValue(),
                    entitlement.getType(),
                    entitlement.getDisplay(),
                    entitlement.isPrimaryFlag()));
        }
        return entitlementList;
    }

    private static List<Map<String, Object>> roleListToMap(List<ScimUserRole> roles) {
        List<Map<String, Object>> roleList = new ArrayList<>(roles.size());
        for (ScimUserRole role : roles) {
            roleList.add(multiValueToMap(role.getValue(), role.getType(), role.getDisplay(), role.isPrimaryFlag()));
        }
        return roleList;
    }

    private static List<Map<String, Object>> imListToMap(List<ScimUserIm> ims) {
        List<Map<String, Object>> imList = new ArrayList<>(ims.size());
        for (ScimUserIm im : ims) {
            imList.add(multiValueToMap(im.getValue(), im.getType(), im.getDisplay(), im.isPrimaryFlag()));
        }
        return imList;
    }

    private static List<Map<String, Object>> photoListToMap(List<ScimUserPhoto> photos) {
        List<Map<String, Object>> photoList = new ArrayList<>(photos.size());
        for (ScimUserPhoto photo : photos) {
            photoList.add(multiValueToMap(photo.getValue(), photo.getType(), photo.getDisplay(), photo.isPrimaryFlag()));
        }
        return photoList;
    }

    private static List<Map<String, Object>> certificateListToMap(List<ScimUserX509Certificate> certificates) {
        List<Map<String, Object>> certificateList = new ArrayList<>(certificates.size());
        for (ScimUserX509Certificate certificate : certificates) {
            certificateList.add(multiValueToMap(
                    certificate.getValue(),
                    certificate.getType(),
                    certificate.getDisplay(),
                    certificate.isPrimaryFlag()));
        }
        return certificateList;
    }

    private static Map<String, Object> userNameToMap(ScimUser user) {
        if (user.getNameFormatted() == null
                && user.getNameFamilyName() == null
                && user.getNameGivenName() == null
                && user.getNameMiddleName() == null
                && user.getNameHonorificPrefix() == null
                && user.getNameHonorificSuffix() == null) {
            return Map.of();
        }
        Map<String, Object> name = new LinkedHashMap<>(6, 1.0f);
        name.put("formatted", user.getNameFormatted());
        name.put("familyName", user.getNameFamilyName());
        name.put("givenName", user.getNameGivenName());
        name.put("middleName", user.getNameMiddleName());
        name.put("honorificPrefix", user.getNameHonorificPrefix());
        name.put("honorificSuffix", user.getNameHonorificSuffix());
        return name;
    }

    private static Map<String, Object> enterpriseToMap(ScimUser user) {
        if (user.getEnterpriseEmployeeNumber() == null
                && user.getEnterpriseCostCenter() == null
                && user.getEnterpriseOrganization() == null
                && user.getEnterpriseDivision() == null
                && user.getEnterpriseDepartment() == null
                && user.getEnterpriseManagerValue() == null
                && user.getEnterpriseManagerRef() == null
                && user.getEnterpriseManagerDisplay() == null) {
            return Map.of();
        }
        Map<String, Object> enterprise = new LinkedHashMap<>(6, 1.0f);
        enterprise.put("employeeNumber", user.getEnterpriseEmployeeNumber());
        enterprise.put("costCenter", user.getEnterpriseCostCenter());
        enterprise.put("organization", user.getEnterpriseOrganization());
        enterprise.put("division", user.getEnterpriseDivision());
        enterprise.put("department", user.getEnterpriseDepartment());
        Map<String, Object> manager = new LinkedHashMap<>(3, 1.0f);
        manager.put(KEY_VALUE, user.getEnterpriseManagerValue());
        manager.put("ref", user.getEnterpriseManagerRef());
        manager.put(KEY_DISPLAY, user.getEnterpriseManagerDisplay());
        enterprise.put("manager", manager);
        return enterprise;
    }

    private static Map<String, Object> addressToMap(ScimUserAddress address) {
        Map<String, Object> map = new LinkedHashMap<>(8, 1.0f);
        map.put("formatted", address.getFormatted());
        map.put("streetAddress", address.getStreetAddress());
        map.put("locality", address.getLocality());
        map.put("region", address.getRegion());
        map.put("postalCode", address.getPostalCode());
        map.put("country", address.getCountry());
        map.put(KEY_TYPE, address.getType());
        map.put("primary", address.isPrimaryFlag());
        return map;
    }

    private static Map<String, Object> multiValueToMap(String value, String type, String display, boolean primary) {
        Map<String, Object> map = new LinkedHashMap<>(4, 1.0f);
        map.put(KEY_VALUE, value);
        map.put(KEY_TYPE, type);
        map.put(KEY_DISPLAY, display);
        map.put("primary", primary);
        return map;
    }

    private static <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }

    private static Map<String, Object> metaToMap(Instant createdAt, Instant lastModified, Long version) {
        Map<String, Object> meta = new LinkedHashMap<>(3, 1.0f);
        meta.put(KEY_CREATED_AT, createdAt != null ? createdAt.toString() : null);
        meta.put(KEY_LAST_MODIFIED, lastModified != null ? lastModified.toString() : null);
        meta.put("version", version);
        return meta;
    }
}