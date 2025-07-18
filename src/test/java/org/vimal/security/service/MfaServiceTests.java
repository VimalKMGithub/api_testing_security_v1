package org.vimal.security.service;

import com.google.zxing.NotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;
import org.vimal.security.BaseTest;
import org.vimal.security.enums.MfaMethods;
import org.vimal.security.helper.AuthCallsHelper;
import org.vimal.security.helper.CallsUsingGlobalAdminUserHelper;
import org.vimal.security.helper.InvalidInputsHelper;
import org.vimal.security.helper.MfaCallsHelper;
import org.vimal.security.util.EmailReaderUtil;
import org.vimal.security.util.QRUtil;
import org.vimal.security.util.TOTPUtil;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.UUID;

import static org.hamcrest.Matchers.*;

public class MfaServiceTests extends BaseTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(MfaServiceTests.class);

    @Test
    public void test_SendOtpToEnableEmailMfa_Success() {
        var user = createTestUserRandomValidEmail();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to request OTP to enable email MFA for user: '{}'", user.getUsername());
        var response = MfaCallsHelper.sendOtpToEnableEmailMfa(accessToken);
        LOGGER.info("Validating response for requesting OTP to enable email MFA for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("OTP sent to your registered email address. Please check your email to continue"));
    }

    @Test
    public void test_SendOtpToEnableEmailMfa_EmailMfaIsAlreadyEnabled() throws Exception {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken).then().statusCode(200);
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "OTP to verify Email MFA");
        var response = MfaCallsHelper.verifyEmailOtp(otp, stateToken);
        response.then().statusCode(200);
        LOGGER.info("Attempting to request OTP to enable email MFA when email MFA is already enabled of user: '{}'", user.getUsername());
        response = MfaCallsHelper.sendOtpToEnableEmailMfa(response.jsonPath().getString("access_token"));
        LOGGER.info("Validating response for requesting OTP to enable email MFA when email MFA is already enabled of user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email Mfa is already enabled"));
    }

    @Test
    public void test_VerifyOtpToEnableEmailMfa_Success() throws Exception {
        var user = createTestUserRandomValidEmail();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Getting OTP to enable email MFA for user: '{}'", user.getUsername());
        MfaCallsHelper.sendOtpToEnableEmailMfa(accessToken).then().statusCode(200);
        LOGGER.info("Extracting OTP from email to enable email MFA for user: '{}'", user.getUsername());
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "Otp to enable email mfa");
        LOGGER.info("Attempting to verify OTP to enable email MFA for user: '{}'", user.getUsername());
        var response = MfaCallsHelper.verifyOtpToEnableEmailMfa(accessToken, otp);
        LOGGER.info("Validating response for verifying OTP to enable email MFA for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Email Mfa enabled successfully. Please log in again to continue"));
        LOGGER.info("Attempting to fetch user details to verify email MFA is enabled for user: '{}'", user.getUsername());
        response = CallsUsingGlobalAdminUserHelper.getUser(user.getUsername());
        LOGGER.info("Validating response for fetching user details to verify email MFA is enabled for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("mfaEnabled", equalTo(true)).body("mfaMethods", contains(MfaMethods.EMAIL.name()));
    }

    @Test
    public void test_VerifyOtpToEnableEmailMfa_InvalidInputs() throws Exception {
        var user = createTestUserRandomValidEmail();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            LOGGER.info("Attempting to verify OTP to enable email MFA for user: '{}' with invalid OTP: '{}'", user.getUsername(), entry);
            var response = MfaCallsHelper.verifyOtpToEnableEmailMfa(accessToken, entry);
            LOGGER.info("Validating response for verifying OTP to enable email MFA for user: '{}' with invalid OTP: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid OTP"));
        }
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken).then().statusCode(200);
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "OTP to verify Email MFA");
        var response = MfaCallsHelper.verifyEmailOtp(otp, stateToken);
        response.then().statusCode(200);
        accessToken = response.jsonPath().getString("access_token");
        LOGGER.info("Attempting to verify OTP to enable email MFA when email MFA is already enabled of user: '{}'", user.getUsername());
        response = MfaCallsHelper.verifyOtpToEnableEmailMfa(accessToken, "123456");
        LOGGER.info("Validating response for verifying OTP to enable email MFA when email MFA is already enabled of user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email Mfa is already enabled"));
    }

    @Test
    public void test_SendOtpToVerifyEmailMfa_Success() {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to request OTP to verify email MFA for user: '{}'", user.getUsername());
        var response = MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken);
        LOGGER.info("Validating response for requesting OTP to verify email MFA for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("OTP sent to your registered email address. Please check your email to continue"));
    }

    @Test
    public void test_SendOtpToVerifyEmailMfa_InvalidInputs() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var uuid = UUID.randomUUID().toString();
        LOGGER.info("Attempting to request OTP to verify email MFA for user: '{}' with invalid state token: '{}'", user.getUsername(), uuid);
        var response = MfaCallsHelper.sendOtpToVerifyEmailMfa(uuid);
        LOGGER.info("Validating response for requesting OTP to verify email MFA for user: '{}' with invalid state token: '{}'\n{}", user.getUsername(), uuid, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired state token"));
        for (var entry : InvalidInputsHelper.invalidUuids()) {
            LOGGER.info("Attempting to request OTP to verify email MFA for user: '{}' with invalid state token: '{}'", user.getUsername(), entry);
            response = MfaCallsHelper.sendOtpToVerifyEmailMfa(entry);
            LOGGER.info("Validating response for requesting OTP to verify email MFA for user: '{}' with invalid state token: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid state token"));
        }
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Enabling Auth App MFA of user: '{}'", user.getUsername());
        response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to request OTP to verify email MFA for user: '{}' when Auth App MFA is enabled", user.getUsername());
        response = MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken);
        LOGGER.info("Validating response for requesting OTP to verify email MFA for user: '{}' when Auth App MFA is enabled\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email Mfa is not enabled"));
    }

    @Test
    public void test_VerifyEmailOtp_Success() throws Exception {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        LOGGER.info("Requesting to send OTP to verify email MFA for user: '{}'", user.getUsername());
        MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken).then().statusCode(200);
        LOGGER.info("Extracting OTP from email to verify email MFA for user: '{}'", user.getUsername());
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "OTP to verify Email MFA");
        LOGGER.info("Attempting to verify email OTP for user: '{}'", user.getUsername());
        var response = MfaCallsHelper.verifyEmailOtp(otp, stateToken);
        LOGGER.info("Validating response for verifying email OTP for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .body("expires_in_seconds", equalTo(1800))
                .body("token_type", containsString("Bearer"));
    }

    @Test
    public void test_VerifyEmailOtp_InvalidInputs() throws Exception {
        var user = createTestUser();
        var uuid = UUID.randomUUID().toString();
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            LOGGER.info("Attempting to verify email OTP for user: '{}' with invalid OTP: '{}'", user.getUsername(), entry);
            var response = MfaCallsHelper.verifyEmailOtp(entry, uuid);
            LOGGER.info("Validating response for verifying email OTP for user: '{}' with invalid OTP: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid OTP or state token"));
        }
        for (var entry : InvalidInputsHelper.invalidUuids()) {
            LOGGER.info("Attempting to verify email OTP for user: '{}' with invalid state token: '{}'", user.getUsername(), entry);
            var response = MfaCallsHelper.verifyEmailOtp("123456", entry);
            LOGGER.info("Validating response for verifying email OTP for user: '{}' with invalid state token: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid OTP or state token"));
        }
        LOGGER.info("Attempting to verify email OTP for user: '{}' with OTP: '{}' and invalid state token: '{}'", user.getUsername(), "123456", uuid);
        var response = MfaCallsHelper.verifyEmailOtp("123456", uuid);
        LOGGER.info("Validating response for verifying email OTP for user: '{}' with invalid state token: '{}'\n{}", user.getUsername(), uuid, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired state token"));
        LOGGER.info("Enabling auth App MFA of user: '{}'", user.getUsername());
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to verify email OTP for user: '{}' when Auth App MFA is enabled", user.getUsername());
        response = MfaCallsHelper.verifyEmailOtp("123456", stateToken);
        LOGGER.info("Validating response for verifying email OTP for user: '{}' when Auth App MFA is enabled\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email Mfa is not enabled"));
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to verify email OTP for user: '{}' with wrong OTP", user.getUsername());
        response = MfaCallsHelper.verifyEmailOtp("123456", stateToken);
        LOGGER.info("Validating response for verifying email OTP for user: '{}' with wrong OTP\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired OTP"));
    }

    @Test
    public void test_VerifyEmailOtp_LockedAfterMaxFailedMfaLoginAttempts() {
        var user = createTestUser();
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        var maxFailedAttempts = 3;
        LOGGER.info("Simulating failed attempts to verify email OTP for user: '{}'", user.getUsername());
        for (int i = 1; i <= maxFailedAttempts; i++) {
            LOGGER.info("Attempt '{}': Verifying email OTP with wrong OTP for user: '{}'", i, user.getUsername());
            var response = MfaCallsHelper.verifyEmailOtp("123456", stateToken);
            LOGGER.info("Validating response for attempt '{}': Verifying email OTP with wrong OTP for user: '{}'\n{}", i, user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Expired OTP"));
        }
        LOGGER.info("Attempting to verify email OTP after exceeding max failed attempts for user: '{}'", user.getUsername());
        var response = MfaCallsHelper.verifyEmailOtp("123456", stateToken);
        LOGGER.info("Validating response for verifying email OTP after exceeding max failed attempts for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Account is locked due to too many failed mfa attempts. Please try again later"));
    }

    @Test
    public void test_DisableEmailMfa_Success() throws Exception {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken).then().statusCode(200);
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "OTP to verify Email MFA");
        var response = MfaCallsHelper.verifyEmailOtp(otp, stateToken);
        response.then().statusCode(200);
        var accessToken = response.jsonPath().getString("access_token");
        LOGGER.info("Attempting to disable email MFA for user: '{}'", user.getUsername());
        response = MfaCallsHelper.disableEmailMfa(accessToken, user.getPassword());
        LOGGER.info("Validating response for disabling email MFA for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Email Mfa disabled successfully. Please log in again to continue"));
        LOGGER.info("Fetching user details to verify email MFA is disabled for user: '{}'", user.getUsername());
        response = CallsUsingGlobalAdminUserHelper.getUser(user.getUsername());
        LOGGER.info("Validating response for fetching user details to verify email MFA is disabled for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("mfaEnabled", equalTo(false)).body("mfaMethods", empty());
    }

    @Test
    public void test_DisableEmailMfa_InvalidInputs() throws Exception {
        var user = createTestUserRandomValidEmail();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to disable email MFA for user: '{}' with invalid password: '{}'", user.getUsername(), entry);
            var response = MfaCallsHelper.disableEmailMfa(accessToken, entry);
            LOGGER.info("Validating response for disabling email MFA for user: '{}' with invalid password: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid password"));
        }
        LOGGER.info("Attempting to disable email MFA for user: '{}' when email MFA is already disabled", user.getUsername());
        var response = MfaCallsHelper.disableEmailMfa(accessToken, user.getPassword());
        LOGGER.info("Validating response for disabling email MFA for user: '{}' when email MFA is already disabled\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email Mfa is already disabled"));
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken).then().statusCode(200);
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "OTP to verify Email MFA");
        response = MfaCallsHelper.verifyEmailOtp(otp, stateToken);
        response.then().statusCode(200);
        accessToken = response.jsonPath().getString("access_token");
        LOGGER.info("Attempting to disable email MFA for user: '{}' with wrong password", user.getUsername());
        response = MfaCallsHelper.disableEmailMfa(accessToken, "WrongPassword@1");
        LOGGER.info("Validating response for disabling email MFA for user: '{}' with wrong password\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Invalid password"));
    }

    @Test
    public void test_GenerateQRCodeForAuthApp_Success() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to generate QR code for Auth App MFA for user: '{}'", user.getUsername());
        var response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        LOGGER.info("Validating response for generating QR code for Auth App MFA for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).contentType("image/png");
    }

    @Test
    public void test_VerifyTotpToSetupAuthApp_Success() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Getting QR code for Auth App MFA for user: '{}'", user.getUsername());
        var response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        LOGGER.info("Extracting secret from QR code for user: '{}'", user.getUsername());
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        LOGGER.info("Attempting to verify TOTP to setup Auth App MFA for user: '{}'", user.getUsername());
        response = MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret));
        LOGGER.info("Validating response for verifying TOTP to setup Auth App MFA for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Authenticator app Mfa enabled successfully. Please log in again to continue"));
        LOGGER.info("Fetching user details to verify Auth App MFA is enabled for user: '{}'", user.getUsername());
        response = CallsUsingGlobalAdminUserHelper.getUser(user.getUsername());
        LOGGER.info("Validating response for fetching user details to verify Auth App MFA is enabled for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("mfaEnabled", equalTo(true)).body("mfaMethods", contains(MfaMethods.AUTHENTICATOR_APP.name()));
    }

    @Test
    public void test_VerifyTotpToSetupAuthApp_InvalidInputs() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            LOGGER.info("Attempting to verify TOTP to setup Auth App MFA for user: '{}' with invalid TOTP: '{}'", user.getUsername(), entry);
            var response = MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, entry);
            LOGGER.info("Validating response for verifying TOTP to setup Auth App MFA for user: '{}' with invalid TOTP: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid TOTP"));
        }
        LOGGER.info("Enabling auth App MFA of user: '{}'", user.getUsername());
        var response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        response = MfaCallsHelper.verifyAuthAppOtp(TOTPUtil.generateCode(secret), stateToken);
        response.then().statusCode(200);
        accessToken = response.jsonPath().getString("access_token");
        LOGGER.info("Attempting to verify TOTP to setup Auth App MFA for user: '{}' when Auth App MFA is already enabled", user.getUsername());
        response = MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, "123456");
        LOGGER.info("Validating response for verifying TOTP to setup Auth App MFA for user: '{}' when Auth App MFA is already enabled\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Authenticator app Mfa is already enabled"));
    }

    @Test
    public void test_VerifyAuthAppOtp_Success() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Enabling Auth App MFA of user: '{}'", user.getUsername());
        var response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to verify Auth App OTP for user: '{}'", user.getUsername());
        response = MfaCallsHelper.verifyAuthAppOtp(TOTPUtil.generateCode(secret), stateToken);
        LOGGER.info("Validating response for verifying Auth App OTP for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .body("expires_in_seconds", equalTo(1800))
                .body("token_type", containsString("Bearer"));
    }

    @Test
    public void test_VerifyAuthAppOtp_InvalidInputs() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var uuid = UUID.randomUUID().toString();
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            LOGGER.info("Attempting to verify Auth App OTP for user: '{}' with invalid TOTP: '{}'", user.getUsername(), entry);
            var response = MfaCallsHelper.verifyAuthAppOtp(entry, uuid);
            LOGGER.info("Validating response for verifying Auth App OTP for user: '{}' with invalid TOTP: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid TOTP or state token"));
        }
        for (var entry : InvalidInputsHelper.invalidUuids()) {
            LOGGER.info("Attempting to verify Auth App OTP for user: '{}' with invalid state token: '{}'", user.getUsername(), entry);
            var response = MfaCallsHelper.verifyAuthAppOtp("123456", entry);
            LOGGER.info("Validating response for verifying Auth App OTP for user: '{}' with invalid state token: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid TOTP or state token"));
        }
        LOGGER.info("Enabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to verify Auth App OTP for user: '{}' when email MFA is enabled", user.getUsername());
        var response = MfaCallsHelper.verifyAuthAppOtp("123456", stateToken);
        LOGGER.info("Validating response for verifying Auth App OTP for user: '{}' when email MFA is enabled\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Authenticator App Mfa is not enabled"));
        LOGGER.info("Disabling email MFA of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.disableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Enabling Auth App MFA of user: '{}'", user.getUsername());
        response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to verify Auth App OTP for user: '{}' with wrong TOTP", user.getUsername());
        response = MfaCallsHelper.verifyAuthAppOtp("123456", stateToken);
        LOGGER.info("Validating response for verifying Auth App OTP for user: '{}' with wrong TOTP\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Invalid TOTP"));
    }

    @Test
    public void test_VerifyAuthAppOtp_LockedAfterMaxFailedMfaLoginAttempts() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        LOGGER.info("Enabling Auth App MFA of user: '{}'", user.getUsername());
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        var response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        int maxFailedAttempts = 3;
        LOGGER.info("Simulating failed attempts to verify Auth App OTP for user: '{}'", user.getUsername());
        for (int i = 1; i <= maxFailedAttempts; i++) {
            LOGGER.info("Attempt '{}': Verifying Auth App OTP with wrong TOTP for user: '{}'", i, user.getUsername());
            response = MfaCallsHelper.verifyAuthAppOtp("123456", stateToken);
            LOGGER.info("Validating response for attempt '{}': Verifying Auth App OTP with wrong TOTP for user: '{}'\n{}", i, user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid TOTP"));
        }
        LOGGER.info("Attempting to verify Auth App OTP after exceeding max failed attempts for user: '{}'", user.getUsername());
        response = MfaCallsHelper.verifyAuthAppOtp("123456", stateToken);
        LOGGER.info("Validating response for verifying Auth App OTP after exceeding max failed attempts for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Account is locked due to too many failed mfa attempts. Please try again later"));
    }

    @Test
    public void test_DisableAuthApp_Success() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Enabling Auth App MFA of user: '{}'", user.getUsername());
        var response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        response = MfaCallsHelper.verifyAuthAppOtp(TOTPUtil.generateCode(secret), stateToken);
        response.then().statusCode(200);
        accessToken = response.jsonPath().getString("access_token");
        LOGGER.info("Attempting to disable Auth App MFA for user: '{}'", user.getUsername());
        response = MfaCallsHelper.disableAuthApp(accessToken, user.getPassword());
        LOGGER.info("Validating response for disabling Auth App MFA for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Authenticator app Mfa disabled successfully. Please log in again to continue"));
        LOGGER.info("Fetching user details to verify Auth App MFA is disabled for user: '{}'", user.getUsername());
        response = CallsUsingGlobalAdminUserHelper.getUser(user.getUsername());
        LOGGER.info("Validating response for fetching user details to verify Auth App MFA is disabled for user: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("mfaEnabled", equalTo(false)).body("mfaMethods", empty());
    }

    @Test
    public void test_DisableAuthApp_InvalidInputs() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to disable Auth App MFA for user: '{}' with invalid password: '{}'", user.getUsername(), entry);
            var response = MfaCallsHelper.disableAuthApp(accessToken, entry);
            LOGGER.info("Validating response for disabling Auth App MFA for user: '{}' with invalid password: '{}'\n{}", user.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid password"));
        }
        LOGGER.info("Attempting to disable Auth App MFA for user: '{}' when Auth App MFA is already disabled", user.getUsername());
        var response = MfaCallsHelper.disableAuthApp(accessToken, user.getPassword());
        LOGGER.info("Validating response for disabling Auth App MFA for user: '{}' when Auth App MFA is already disabled\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Authenticator app Mfa is already disabled"));
        LOGGER.info("Enabling Auth App MFA of user: '{}'", user.getUsername());
        response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        response = MfaCallsHelper.verifyAuthAppOtp(TOTPUtil.generateCode(secret), stateToken);
        response.then().statusCode(200);
        accessToken = response.jsonPath().getString("access_token");
        LOGGER.info("Attempting to disable Auth App MFA for user: '{}' with wrong password", user.getUsername());
        response = MfaCallsHelper.disableAuthApp(accessToken, "WrongPassword@1");
        LOGGER.info("Validating response for disabling Auth App MFA for user: '{}' with wrong password\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Invalid password"));
    }
}