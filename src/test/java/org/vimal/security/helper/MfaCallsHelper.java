package org.vimal.security.helper;

import io.restassured.response.Response;
import org.vimal.security.enums.RequestMethods;
import org.vimal.security.util.ApiRequestUtil;

import java.util.Map;

public final class MfaCallsHelper {
    private MfaCallsHelper() {
        throw new AssertionError("Cannot instantiate AuthAppMfaCallsHelper class");
    }

    public static Response sendOtpToEnableEmailMfa(String accessToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/enable/email",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken)
        );
    }

    public static Response verifyOtpToEnableEmailMfa(String accessToken,
                                                     String otp) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/enable/email/verify",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("otp", otp)
        );
    }

    public static Response sendOtpToVerifyEmailMfa(String stateToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/send/email/otp",
                null,
                Map.of("stateToken", stateToken)
        );
    }

    public static Response verifyEmailOtp(String otp,
                                          String stateToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/verify/email/otp",
                null,
                Map.of("otp", otp, "stateToken", stateToken)
        );
    }

    public static Response disableEmailMfa(String accessToken,
                                           String password) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/disable/email",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("password", password)
        );
    }

    public static Response generateQRCodeForAuthApp(String accessToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/enable/authapp",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken)
        );
    }

    public static Response verifyTotpToSetupAuthApp(String accessToken,
                                                    String totp) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/enable/authapp/verify",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("totp", totp)
        );
    }

    public static Response verifyAuthAppOtp(String totp,
                                            String stateToken) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/verify/authapp/otp",
                null,
                Map.of("totp", totp, "stateToken", stateToken)
        );
    }

    public static Response disableAuthApp(String accessToken,
                                          String password) {
        return ApiRequestUtil.executeRequest(
                RequestMethods.POST,
                SubPathsHelper.MFA_SUB_PATH + "/disable/authapp",
                Map.of(CommonConstantsHelper.AUTHORIZATION_HEADER_PREFIX, CommonConstantsHelper.BEARER_PREFIX + accessToken),
                Map.of("password", password)
        );
    }
}