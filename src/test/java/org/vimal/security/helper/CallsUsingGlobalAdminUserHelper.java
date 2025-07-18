package org.vimal.security.helper;

import io.restassured.response.Response;
import org.vimal.security.dto.RoleDto;
import org.vimal.security.dto.UserDto;

import java.util.Set;

import static org.vimal.security.BaseTest.*;

public final class CallsUsingGlobalAdminUserHelper {
    private CallsUsingGlobalAdminUserHelper() {
        throw new AssertionError("Cannot instantiate CallsUsingGlobalAdminUserHelper class");
    }

    public static Response createUsers(Set<UserDto> userDtos) {
        var response = AdminUserCallsHelper.createUsers(GLOBAL_ADMIN_ACCESS_TOKEN, userDtos);
        if (response.statusCode() == 401) {
            GLOBAL_ADMIN_ACCESS_TOKEN = AuthCallsHelper.getAccessToken(GLOBAL_ADMIN_USERNAME, GLOBAL_ADMIN_PASSWORD);
            response = AdminUserCallsHelper.createUsers(GLOBAL_ADMIN_ACCESS_TOKEN, userDtos);
        }
        return response;
    }

    public static Response getUser(String usernameOrEmail) {
        var response = AdminUserCallsHelper.getUser(GLOBAL_ADMIN_ACCESS_TOKEN, usernameOrEmail);
        if (response.statusCode() == 401) {
            GLOBAL_ADMIN_ACCESS_TOKEN = AuthCallsHelper.getAccessToken(GLOBAL_ADMIN_USERNAME, GLOBAL_ADMIN_PASSWORD);
            response = AdminUserCallsHelper.getUser(GLOBAL_ADMIN_ACCESS_TOKEN, usernameOrEmail);
        }
        return response;
    }

    public static Response createRoles(Set<RoleDto> roleDtos) {
        var response = AdminUserCallsHelper.createRoles(GLOBAL_ADMIN_ACCESS_TOKEN, roleDtos);
        if (response.statusCode() == 401) {
            GLOBAL_ADMIN_ACCESS_TOKEN = AuthCallsHelper.getAccessToken(GLOBAL_ADMIN_USERNAME, GLOBAL_ADMIN_PASSWORD);
            response = AdminUserCallsHelper.createRoles(GLOBAL_ADMIN_ACCESS_TOKEN, roleDtos);
        }
        return response;
    }

    public static Response enableEmailMfaForUser(String usernameOrEmail) {
        var response = AdminUserCallsHelper.enableEmailMfaForUser(GLOBAL_ADMIN_ACCESS_TOKEN, usernameOrEmail);
        if (response.statusCode() == 401) {
            GLOBAL_ADMIN_ACCESS_TOKEN = AuthCallsHelper.getAccessToken(GLOBAL_ADMIN_USERNAME, GLOBAL_ADMIN_PASSWORD);
            response = AdminUserCallsHelper.enableEmailMfaForUser(GLOBAL_ADMIN_ACCESS_TOKEN, usernameOrEmail);
        }
        return response;
    }

    public static Response disableEmailMfaForUser(String usernameOrEmail) {
        var response = AdminUserCallsHelper.disableEmailMfaForUser(GLOBAL_ADMIN_ACCESS_TOKEN, usernameOrEmail);
        if (response.statusCode() == 401) {
            GLOBAL_ADMIN_ACCESS_TOKEN = AuthCallsHelper.getAccessToken(GLOBAL_ADMIN_USERNAME, GLOBAL_ADMIN_PASSWORD);
            response = AdminUserCallsHelper.disableEmailMfaForUser(GLOBAL_ADMIN_ACCESS_TOKEN, usernameOrEmail);
        }
        return response;
    }

    public static void deleteUsersLenient(Set<String> usernamesOrEmails) {
        var response = AdminUserCallsHelper.deleteUsersLenient(GLOBAL_ADMIN_ACCESS_TOKEN, usernamesOrEmails);
        if (response.statusCode() == 401) {
            GLOBAL_ADMIN_ACCESS_TOKEN = AuthCallsHelper.getAccessToken(GLOBAL_ADMIN_USERNAME, GLOBAL_ADMIN_PASSWORD);
            AdminUserCallsHelper.deleteUsersLenient(GLOBAL_ADMIN_ACCESS_TOKEN, usernamesOrEmails);
        }
    }

    public static void deleteRolesLenient(Set<String> roleNames) {
        var response = AdminUserCallsHelper.deleteRolesLenient(GLOBAL_ADMIN_ACCESS_TOKEN, roleNames);
        if (response.statusCode() == 401) {
            GLOBAL_ADMIN_ACCESS_TOKEN = AuthCallsHelper.getAccessToken(GLOBAL_ADMIN_USERNAME, GLOBAL_ADMIN_PASSWORD);
            AdminUserCallsHelper.deleteRolesLenient(GLOBAL_ADMIN_ACCESS_TOKEN, roleNames);
        }
    }
}