package org.vimal.security.helper;

import io.restassured.response.Response;
import org.vimal.security.dto.RoleDto;
import org.vimal.security.dto.UserDto;
import org.vimal.security.enums.RequestMethods;
import org.vimal.security.util.ApiRequestUtil;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public final class AdminUserCallsHelper {
    private AdminUserCallsHelper() {
        throw new AssertionError("Cannot instantiate AdminUserCallsHelper class");
    }

    public static Response createUser(String accessToken,
                                      UserDto userDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/create-user",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                userDto
        );
    }

    public static Response createUsers(String accessToken,
                                       Set<UserDto> userDtos) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/create-users",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                userDtos
        );
    }

    public static Response deleteUserByUsername(String accessToken,
                                                String username) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/delete-user-by-username",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("username", username)
        );
    }

    public static Response deleteUserByEmail(String accessToken,
                                             String email) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/delete-user-by-email",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("email", email)
        );
    }

    public static Response deleteUser(String accessToken,
                                      String usernameOrEmail) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/delete-user",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("usernameOrEmail", usernameOrEmail)
        );
    }

    public static Response deleteUsers(String accessToken,
                                       Set<String> usernamesOrEmails) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/delete-users",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                usernamesOrEmails
        );
    }

    public static Response getUserByUsername(String accessToken,
                                             String username) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-user-by-username",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("username", username)
        );
    }

    public static Response getUserByEmail(String accessToken,
                                          String email) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-user-by-email",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("email", email)
        );
    }

    public static Response getUser(String accessToken,
                                   String usernameOrEmail) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-user",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("usernameOrEmail", usernameOrEmail)
        );
    }

    public static Response getUsers(String accessToken,
                                    Set<String> usernamesOrEmails) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-users",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                usernamesOrEmails
        );
    }

    public static Response updateUser(String accessToken,
                                      String usernameOrEmail,
                                      UserDto userDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.PUT,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/update-user",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("usernameOrEmail", usernameOrEmail),
                null,
                userDto
        );
    }

    public static Response updateUsers(String accessToken,
                                       Set<UserDto> userDtos) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.PUT,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/update-users",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                userDtos
        );
    }

    public static Response getPermission(String accessToken,
                                         String permissionName) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-permission",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("permissionName", permissionName)
        );
    }

    public static Response getPermissions(String accessToken,
                                          Set<String> permissionNames) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-permissions",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                permissionNames
        );
    }

    public static Response createRole(String accessToken,
                                      RoleDto roleDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/create-role",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                roleDto
        );
    }

    public static Response createRoles(String accessToken,
                                       Set<RoleDto> roleDtos) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/create-roles",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                roleDtos
        );
    }

    public static Response deleteRole(String accessToken,
                                      String roleName) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/delete-role",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("roleName", roleName)
        );
    }

    public static Response deleteRoles(String accessToken,
                                       Set<String> roleNames) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/delete-roles",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                roleNames
        );
    }

    public static Response getRole(String accessToken,
                                   String roleName) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-role",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("roleName", roleName)
        );
    }

    public static Response getRoles(String accessToken,
                                    Set<String> roleNames) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-roles",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                roleNames
        );
    }

    public static Response updateRole(String accessToken,
                                      RoleDto roleDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.PUT,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/update-role",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                roleDto
        );
    }

    public static Response updateRoles(String accessToken,
                                       Set<RoleDto> roleDtos) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.PUT,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/update-roles",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                roleDtos
        );
    }

    public static Response getAllUsers(String accessToken) {
        return getAllUsers(accessToken, null);
    }

    public static Response getAllUsers(String accessToken,
                                       Integer page) {
        return getAllUsers(accessToken, page, null);
    }

    public static Response getAllUsers(String accessToken,
                                       Integer page,
                                       Integer size) {
        return getAllUsers(accessToken, page, size, null);
    }

    public static Response getAllUsers(String accessToken,
                                       Integer page,
                                       Integer size,
                                       String sort) {
        var queryParams = new HashMap<String, String>();
        if (page != null) queryParams.put("page", page.toString());
        if (size != null) queryParams.put("size", size.toString());
        if (sort != null && !sort.isBlank()) queryParams.put("sort", sort);
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-all-users",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                queryParams
        );
    }

    public static Response getAllPermissions(String accessToken) {
        return getAllPermissions(accessToken, null);
    }

    public static Response getAllPermissions(String accessToken,
                                             Integer page) {
        return getAllPermissions(accessToken, page, null);
    }

    public static Response getAllPermissions(String accessToken,
                                             Integer page,
                                             Integer size) {
        return getAllPermissions(accessToken, page, size, null);
    }

    public static Response getAllPermissions(String accessToken,
                                             Integer page,
                                             Integer size,
                                             String sort) {
        var queryParams = new HashMap<String, String>();
        if (page != null) queryParams.put("page", page.toString());
        if (size != null) queryParams.put("size", size.toString());
        if (sort != null && !sort.isBlank()) queryParams.put("sort", sort);
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-all-permissions",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                queryParams
        );
    }

    public static Response getAllRoles(String accessToken) {
        return getAllRoles(accessToken, null);
    }

    public static Response getAllRoles(String accessToken,
                                       Integer page) {
        return getAllRoles(accessToken, page, null);
    }

    public static Response getAllRoles(String accessToken,
                                       Integer page,
                                       Integer size) {
        return getAllRoles(accessToken, page, size, null);
    }

    public static Response getAllRoles(String accessToken,
                                       Integer page,
                                       Integer size,
                                       String sort) {
        var queryParams = new HashMap<String, String>();
        if (page != null) queryParams.put("page", page.toString());
        if (size != null) queryParams.put("size", size.toString());
        if (sort != null && !sort.isBlank()) queryParams.put("sort", sort);
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-all-roles",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                queryParams
        );
    }

    public static Response enableEmailMfaForUser(String accessToken,
                                                 String usernameOrEmail) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/enable-email-mfa-for-user",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("usernameOrEmail", usernameOrEmail)
        );
    }

    public static Response disableEmailMfaForUser(String accessToken,
                                                  String usernameOrEmail) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/disable-email-mfa-for-user",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("usernameOrEmail", usernameOrEmail)
        );
    }

    public static Response createUsersLenient(String accessToken,
                                              Set<UserDto> userDtos) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/create-users-lenient",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                userDtos
        );
    }

    public static Response deleteUsersLenient(String accessToken,
                                              Set<String> usernamesOrEmails) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/delete-users-lenient",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                usernamesOrEmails
        );
    }

    public static Response getUsersLenient(String accessToken,
                                           Set<String> usernamesOrEmails) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/get-users-lenient",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                usernamesOrEmails
        );
    }

    public static Response updateUsersLenient(String accessToken,
                                              Set<UserDto> userDtos) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.PUT,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/update-users-lenient",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                userDtos
        );
    }

    public static Response deleteRolesLenient(String accessToken,
                                              Set<String> roleNames) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_ADMIN_SUB_PATH + "/delete-roles-lenient",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                roleNames
        );
    }
}