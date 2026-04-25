package de.palsoftware.scim.server.ui.dto;

import java.util.List;

public record UserUpsertRequest(
                String userName,
                String displayName,
                Boolean active,
                String externalId,
                String nameFormatted,
                String nameFamilyName,
                String nameGivenName,
                String nameMiddleName,
                String nameHonorificPrefix,
                String nameHonorificSuffix,
                String nickName,
                String profileUrl,
                String title,
                String userType,
                String preferredLanguage,
                String locale,
                String timezone,
                String password,
                String enterpriseEmployeeNumber,
                String enterpriseCostCenter,
                String enterpriseOrganization,
                String enterpriseDivision,
                String enterpriseDepartment,
                String enterpriseManagerValue,
                String enterpriseManagerRef,
                String enterpriseManagerDisplay,
                List<MultiValue> emails,
                List<MultiValue> phoneNumbers,
                List<Address> addresses,
                List<MultiValue> entitlements,
                List<MultiValue> roles,
                List<MultiValue> ims,
                List<MultiValue> photos,
                List<MultiValue> x509Certificates) {
        public record MultiValue(
                        String value,
                        String type,
                        String display,
                        Boolean primary) {
        }

        public record Address(
                        String formatted,
                        String streetAddress,
                        String locality,
                        String region,
                        String postalCode,
                        String country,
                        String type,
                        Boolean primary) {
        }
}
