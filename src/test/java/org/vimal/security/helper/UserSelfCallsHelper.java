package org.vimal.security.helper;

import io.restassured.response.Response;
import org.vimal.security.dto.ResetPwdDto;
import org.vimal.security.dto.UserDto;
import org.vimal.security.dto.UserSelfUpdationDto;
import org.vimal.security.enums.RequestMethods;
import org.vimal.security.util.ApiRequestUtil;

import java.util.Map;

public final class UserSelfCallsHelper {
    private UserSelfCallsHelper() {
        throw new AssertionError("Cannot instantiate UserSelfCallsHelper class");
    }

    public static Response register(UserDto user) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/register",
                null,
                null,
                null,
                user
        );
    }

    public static Response verifyEmail(String token) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/verify-email",
                null,
                Map.of("token", token)
        );
    }

    public static Response resendEmailVerificationByUsername(String username) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/resend-email-verification-by-username",
                null,
                Map.of("username", username)
        );
    }

    public static Response resendEmailVerificationByEmail(String email) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/resend-email-verification-by-email",
                null,
                Map.of("email", email)
        );
    }

    public static Response resendEmailVerification(String usernameOrEmail) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/resend-email-verification",
                null,
                Map.of("usernameOrEmail", usernameOrEmail)
        );
    }

    public static Response forgotPasswordByUsername(String username) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/forgot-password-by-username",
                null,
                Map.of("username", username)
        );
    }

    public static Response forgotPasswordByEmail(String email) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/forgot-password-by-email",
                null,
                Map.of("email", email)
        );
    }

    public static Response forgotPassword(String usernameOrEmail) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/forgot-password",
                null,
                Map.of("usernameOrEmail", usernameOrEmail)
        );
    }

    public static Response resetPasswordUsingUsername(ResetPwdDto resetPwdDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/reset-password-using-username",
                null,
                null,
                null,
                resetPwdDto
        );
    }

    public static Response resetPasswordUsingEmail(ResetPwdDto resetPwdDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/reset-password-using-email",
                null,
                null,
                null,
                resetPwdDto
        );
    }

    public static Response resetPassword(ResetPwdDto resetPwdDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/reset-password",
                null,
                null,
                null,
                resetPwdDto
        );
    }

    public static Response resetPasswordUsingOldPassword(String accessToken,
                                                         ResetPwdDto resetPwdDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/reset-password-using-old-password",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                resetPwdDto
        );
    }

    public static Response emailChangeRequest(String accessToken,
                                              String email) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/email-change-request",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("email", email)
        );
    }

    public static Response verifyEmailChange(String accessToken,
                                             String otp,
                                             String password) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/verify-email-change",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("otp", otp, "password", password)
        );
    }

    public static Response getYourself(String accessToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.GET,
                SubPathsHelper.USER_SELF_SUB_PATH + "/get-yourself",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken)
        );
    }

    public static Response deleteAccountByPassword(String accessToken,
                                                   String password) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_SELF_SUB_PATH + "/delete-account-by-password",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("password", password)
        );
    }

    public static Response sendEmailOtpToDeleteAccount(String accessToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.USER_SELF_SUB_PATH + "/send-email-otp-to-delete-account",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken)
        );
    }

    public static Response verifyEmailOtpToDeleteAccount(String accessToken,
                                                         String password,
                                                         String otp) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_SELF_SUB_PATH + "/verify-email-otp-to-delete-account",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("password", password, "otp", otp)
        );
    }

    public static Response deleteAccountByAuthAppTotp(String accessToken,
                                                      String password,
                                                      String totp) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.DELETE,
                SubPathsHelper.USER_SELF_SUB_PATH + "/delete-account-by-auth-app-totp",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("password", password, "totp", totp)
        );
    }

    public static Response updateYourselfBasic(String accessToken,
                                               UserSelfUpdationDto userDto) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.PUT,
                SubPathsHelper.USER_SELF_SUB_PATH + "/update-yourself-basic",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                null,
                null,
                userDto
        );
    }
}