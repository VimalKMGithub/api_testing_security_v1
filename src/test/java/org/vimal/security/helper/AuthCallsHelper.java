package org.vimal.security.helper;

import io.restassured.response.Response;
import org.vimal.security.enums.RequestMethods;
import org.vimal.security.util.ApiRequestUtil;

import java.util.Map;

public final class AuthCallsHelper {
    private AuthCallsHelper() {
        throw new AssertionError("Cannot instantiate AuthCallsHelper class");
    }

    public static Response loginByUsername(String username,
                                           String password) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.AUTH_SUB_PATH + "/login-by-username",
                null,
                Map.of("username", username, "password", password)
        );
    }

    public static Response loginByEmail(String email,
                                        String password) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.AUTH_SUB_PATH + "/login-by-email",
                null,
                Map.of("email", email, "password", password)
        );
    }

    public static Response login(String usernameOrEmail,
                                 String password) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.AUTH_SUB_PATH + "/login",
                null,
                Map.of("usernameOrEmail", usernameOrEmail, "password", password)
        );
    }

    public static Response logout(String accessToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.AUTH_SUB_PATH + "/logout",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken)
        );
    }

    public static Response refreshAccessToken(String refreshToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.AUTH_SUB_PATH + "/refresh-access-token",
                null,
                Map.of("refreshToken", refreshToken)
        );
    }

    public static Response revokeAccessToken(String accessToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.AUTH_SUB_PATH + "/revoke-access-token",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken)
        );
    }

    public static Response revokeRefreshToken(String refreshToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.AUTH_SUB_PATH + "/revoke-refresh-token",
                null,
                Map.of("refreshToken", refreshToken)
        );
    }

    public static String getAccessToken(String usernameOrEmail,
                                        String password) {
        var response = login(usernameOrEmail, password);
        response.then().statusCode(200);
        return response.jsonPath().getString("access_token");
    }

    public static String getRefreshToken(String usernameOrEmail,
                                         String password) {
        var response = login(usernameOrEmail, password);
        response.then().statusCode(200);
        return response.jsonPath().getString("refresh_token");
    }

    public static String getStateToken(String usernameOrEmail,
                                       String password) {
        var response = login(usernameOrEmail, password);
        response.then().statusCode(200);
        return response.jsonPath().getString("state_token");
    }
}