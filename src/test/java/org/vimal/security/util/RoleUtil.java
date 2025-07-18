package org.vimal.security.util;

import org.vimal.security.dto.UserDto;
import org.vimal.security.enums.Roles;

import java.util.Comparator;
import java.util.Set;

public final class RoleUtil {
    private RoleUtil() {
        throw new AssertionError("Cannot instantiate RoleUtil class");
    }

    public static String getHighestAdminRole(UserDto user) {
        return getHighestAdminRole(user.getRoles());
    }

    public static String getHighestAdminRole(Set<String> roles) {
        if (roles != null) {
            return roles.stream()
                    .filter(Roles.TOP_ROLES::contains)
                    .min(Comparator.comparingInt(Roles.TOP_ROLES::indexOf))
                    .orElse(null);
        }
        return null;
    }
}