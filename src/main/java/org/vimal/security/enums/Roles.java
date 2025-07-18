package org.vimal.security.enums;

import java.util.List;

public enum Roles {
    ROLE_SUPER_ADMIN,
    ROLE_ADMIN,
    ROLE_MANAGE_ROLES,
    ROLE_MANAGE_USERS,
    ROLE_MANAGE_PERMISSIONS;
    
    public static final List<String> TOP_ROLES = List.of(
            ROLE_SUPER_ADMIN.name(),
            ROLE_ADMIN.name()
    );
}