package org.vimal.security.service;

import com.google.zxing.NotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;
import org.vimal.security.BaseTest;
import org.vimal.security.dto.ResetPwdDto;
import org.vimal.security.dto.UserDto;
import org.vimal.security.dto.UserSelfUpdationDto;
import org.vimal.security.helper.*;
import org.vimal.security.util.*;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Set;
import java.util.UUID;

import static org.hamcrest.Matchers.*;

public class UserSelfServiceTests extends BaseTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserSelfServiceTests.class);

    @Test
    public void test_Register_Success() {
        var user = DtosHelper.createRandomUserDtoWithRandomValidEmail();
        TEST_USERS.add(user);
        try {
            LOGGER.info("Attempting to register user:\n{}", ToJsonForLoggingUtil.toJson(user));
            var response = UserSelfCallsHelper.register(user);
            LOGGER.info("Validating response for successful registration:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", containsString("Registration successful. A link sent to your registered email to verify your email"))
                    .body("user.username", equalTo(user.getUsername()))
                    .body("user.email", equalTo(user.getEmail()))
                    .body("user.createdBy", equalTo("Self registration"))
                    .body("user.updatedBy", equalTo("Self registration"));
        } finally {
            CleanUpHelper.cleanUpTestUsers(user);
        }
    }

    @Test
    public void test_Register_InvalidInputs() {
        var user = new UserDto();
        LOGGER.info("Attempting to register user with null username:\n{}", ToJsonForLoggingUtil.toJson(user));
        var response = UserSelfCallsHelper.register(user);
        LOGGER.info("Validating response for trying to register user with null username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            user.setUsername(entry);
            LOGGER.info("Attempting to register user with invalid username: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(user));
            response = UserSelfCallsHelper.register(user);
            LOGGER.info("Validating response for trying to register user with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        user.setUsername("user_" + uniqueString);
        LOGGER.info("Attempting to register user with null password:\n{}", ToJsonForLoggingUtil.toJson(user));
        response = UserSelfCallsHelper.register(user);
        LOGGER.info("Validating response for trying to register user with null password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            user.setPassword(entry);
            LOGGER.info("Attempting to register user with invalid password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(user));
            response = UserSelfCallsHelper.register(user);
            LOGGER.info("Validating response for trying to register user with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        user.setPassword("ValidPassword123!_" + uniqueString);
        LOGGER.info("Attempting to register user with null email:\n{}", ToJsonForLoggingUtil.toJson(user));
        response = UserSelfCallsHelper.register(user);
        LOGGER.info("Validating response for trying to register user with null email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            user.setEmail(entry);
            LOGGER.info("Attempting to register user with invalid email: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(user));
            response = UserSelfCallsHelper.register(user);
            LOGGER.info("Validating response for trying to register user with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        user.setEmail(uniqueString + "@example.com");
        LOGGER.info("Attempting to register user with null first name:\n{}", ToJsonForLoggingUtil.toJson(user));
        response = UserSelfCallsHelper.register(user);
        LOGGER.info("Validating response for trying to register user with null first name:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidNames()) {
            user.setFirstName(entry);
            LOGGER.info("Attempting to register user with invalid first name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(user));
            response = UserSelfCallsHelper.register(user);
            LOGGER.info("Validating response for trying to register user with invalid first name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        user.setFirstName("F");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            user.setMiddleName(entry);
            LOGGER.info("Attempting to register user with invalid middle name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(user));
            response = UserSelfCallsHelper.register(user);
            LOGGER.info("Validating response for trying to register user with invalid middle name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        user.setMiddleName("M");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            user.setLastName(entry);
            LOGGER.info("Attempting to register user with invalid last name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(user));
            response = UserSelfCallsHelper.register(user);
            LOGGER.info("Validating response for trying to register user with invalid last name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
    }

    @Test
    public void test_Register_UsernameAlreadyTaken_EmailAlreadyTaken() {
        var user = createTestUser();
        var originalUsername = user.getUsername();
        LOGGER.info("Attempting to register user with same username: '{}'\n{}", user.getUsername(), ToJsonForLoggingUtil.toJson(user));
        var response = UserSelfCallsHelper.register(user);
        LOGGER.info("Validating response for trying to register user with same username: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Username: '" + user.getUsername() + "' already taken"));
        user.setUsername("new_" + user.getUsername());
        LOGGER.info("Attempting to register user with same email: '{}'\n{}", user.getEmail(), ToJsonForLoggingUtil.toJson(user));
        response = UserSelfCallsHelper.register(user);
        LOGGER.info("Validating response for trying to register user with same email: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email: '" + user.getEmail() + "' already taken"));
        user.setUsername(originalUsername);
    }

    @Test
    public void test_VerifyEmail_Success() throws Exception {
        var user = DtosHelper.createRandomUserDtoWithRandomValidEmail();
        TEST_USERS.add(user);
        try {
            LOGGER.info("Registering user:\n{}", ToJsonForLoggingUtil.toJson(user));
            UserSelfCallsHelper.register(user).then().statusCode(200);
            LOGGER.info("Extracting email verification token from email ...");
            var token = EmailReaderUtil.getUUIDTypeTokenFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "Email Verification after registration");
            LOGGER.info("Attempting to verify email with token: '{}'", token);
            var response = UserSelfCallsHelper.verifyEmail(token);
            LOGGER.info("Validating response for successful email verification:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", containsString("Registered email verified successfully"))
                    .body("user.username", equalTo(user.getUsername()))
                    .body("user.email", equalTo(user.getEmail()))
                    .body("user.emailVerified", equalTo(true));
        } finally {
            CleanUpHelper.cleanUpTestUsers(user);
        }
    }

    @Test
    public void test_VerifyEmail_InvalidInputs() {
        var uuid = UUID.randomUUID().toString();
        LOGGER.info("Attempting to verify email with invalid token: '{}'", uuid);
        var response = UserSelfCallsHelper.verifyEmail(uuid);
        LOGGER.info("Validating response for trying to verify email with invalid token: '{}'\n{}", uuid, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired verification link"));
        for (var entry : InvalidInputsHelper.invalidUuids()) {
            LOGGER.info("Attempting to verify email with invalid token: '{}'", entry);
            response = UserSelfCallsHelper.verifyEmail(entry);
            LOGGER.info("Validating response for trying to verify email with invalid token: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid verification link"));
        }
    }

    @Test
    public void test_ResendEmailVerificationByUsername_Success() {
        var user = DtosHelper.createRandomUserDtoWithRandomValidEmail();
        user.setEmailVerified(false);
        TEST_USERS.add(user);
        createTestUser(user);
        LOGGER.info("Attempting to resend email verification by username: '{}'", user.getUsername());
        var response = UserSelfCallsHelper.resendEmailVerificationByUsername(user.getUsername());
        LOGGER.info("Validating response for successful email verification resend by username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Verification link resent to your registered email"));
    }

    @Test
    public void test_ResendEmailVerificationByUsername_InvalidInputs() {
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to resend email verification by invalid username: '{}'", entry);
            var response = UserSelfCallsHelper.resendEmailVerificationByUsername(entry);
            LOGGER.info("Validating response for trying to resend email verification by invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User with username: '" + entry + "' not found"));
        }
        String notExistingUsername = "NonExistingUser_" + DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to resend email verification by non existing username: '{}'", notExistingUsername);
        var response = UserSelfCallsHelper.resendEmailVerificationByUsername(notExistingUsername);
        LOGGER.info("Validating response for trying to resend email verification by non existing username: '{}'\n{}", notExistingUsername, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User with username: '" + notExistingUsername + "' not found"));
    }

    @Test
    public void test_ResendEmailVerificationByUsername_EmailAlreadyVerified() {
        var user = createTestUser();
        LOGGER.info("Attempting to resend email verification by username: '{}' when email is already verified", user.getUsername());
        var response = UserSelfCallsHelper.resendEmailVerificationByUsername(user.getUsername());
        LOGGER.info("Validating response for trying to resend email verification by username: '{}' when email is already verified\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Registered email is already verified"));
    }

    @Test
    public void test_ResendEmailVerificationByEmail_Success() {
        var user = DtosHelper.createRandomUserDtoWithRandomValidEmail();
        user.setEmailVerified(false);
        TEST_USERS.add(user);
        createTestUser(user);
        LOGGER.info("Attempting to resend email verification by email: '{}'", user.getEmail());
        var response = UserSelfCallsHelper.resendEmailVerificationByEmail(user.getEmail());
        LOGGER.info("Validating response for successful email verification resend by email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Verification link resent to your registered email"));
    }

    @Test
    public void test_ResendEmailVerificationByEmail_InvalidInputs() {
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to resend email verification by invalid email: '{}'", entry);
            var response = UserSelfCallsHelper.resendEmailVerificationByEmail(entry);
            LOGGER.info("Validating response for trying to resend email verification by invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User with email: '" + entry + "' not found"));
        }
        var nonExistingEmail = "nonexisting_" + DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric().toLowerCase() + "@example.com";
        LOGGER.info("Attempting to resend email verification by non existing email: '{}'", nonExistingEmail);
        var response = UserSelfCallsHelper.resendEmailVerificationByEmail(nonExistingEmail);
        LOGGER.info("Validating response for trying to resend email verification by non existing email: '{}'\n{}", nonExistingEmail, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User with email: '" + nonExistingEmail + "' not found"));
    }

    @Test
    public void test_ResendEmailVerificationByEmail_EmailAlreadyVerified() {
        var user = createTestUser();
        LOGGER.info("Attempting to resend email verification by email: '{}' when email is already verified", user.getEmail());
        var response = UserSelfCallsHelper.resendEmailVerificationByEmail(user.getEmail());
        LOGGER.info("Validating response for trying to resend email verification by email: '{}' when email is already verified\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Registered email is already verified"));
    }

    @Test
    public void test_ResendEmailVerification_Success() {
        var user = DtosHelper.createRandomUserDtoWithRandomValidEmail();
        user.setEmailVerified(false);
        TEST_USERS.add(user);
        createTestUser(user);
        LOGGER.info("Attempting to resend email verification by username: '{}'", user.getUsername());
        var response = UserSelfCallsHelper.resendEmailVerification(user.getUsername());
        LOGGER.info("Validating response for successful email verification resend by username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Verification link resent to your registered email"));
        LOGGER.info("Attempting to resend email verification by email: '{}'", user.getEmail());
        response = UserSelfCallsHelper.resendEmailVerificationByEmail(user.getEmail());
        LOGGER.info("Validating response for successful email verification resend by email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Verification link resent to your registered email"));
    }

    @Test
    public void test_ResendEmailVerification_InvalidInputs() {
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to resend email verification by invalid input(username/email): '{}'", entry);
            var response = UserSelfCallsHelper.resendEmailVerification(entry);
            LOGGER.info("Validating response for trying to resend email verification by invalid input(username/email): '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("not found"));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to resend email verification by invalid input(username/email): '{}'", entry);
            var response = UserSelfCallsHelper.resendEmailVerification(entry);
            LOGGER.info("Validating response for trying to resend email verification by invalid input(username/email): '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("not found"));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to resend email verification by non existing username: '{}'", uniqueString);
        var response = UserSelfCallsHelper.resendEmailVerification("NonExistingUser_" + uniqueString);
        LOGGER.info("Validating response for trying to resend email verification by non existing username: '{}'\n{}", "NonExistingUser_" + uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("not found"));
        LOGGER.info("Attempting to resend email verification by non existing email: '{}'", "user_" + uniqueString.toLowerCase() + "@example.com");
        response = UserSelfCallsHelper.resendEmailVerification("user_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Validating response for trying to resend email verification by non existing email: '{}'\n{}", "user_" + uniqueString.toLowerCase() + "@example.com", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("not found"));
    }

    @Test
    public void test_ResendEmailVerification_EmailAlreadyVerified() {
        var user = createTestUser();
        LOGGER.info("Attempting to resend email verification by username: '{}' when email is already verified", user.getUsername());
        var response = UserSelfCallsHelper.resendEmailVerification(user.getUsername());
        LOGGER.info("Validating response for trying to resend email verification by username: '{}' when email is already verified\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Registered email is already verified"));
        LOGGER.info("Attempting to resend email verification by email: '{}' when email is already verified", user.getEmail());
        response = UserSelfCallsHelper.resendEmailVerification(user.getEmail());
        LOGGER.info("Validating response for trying to resend email verification by email: '{}' when email is already verified\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Registered email is already verified"));
    }

    @Test
    public void test_ForgotPasswordByUsername_Success() {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Attempting to request password reset by username: '{}'", user.getUsername());
        var response = UserSelfCallsHelper.forgotPasswordByUsername(user.getUsername());
        LOGGER.info("Validating response for successful password reset request by username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("OTP sent to your registered email for password reset"));
    }

    @Test
    public void test_ForgotPasswordByUsername_InvalidInputs() {
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to request password reset by invalid username: '{}'", entry);
            var response = UserSelfCallsHelper.forgotPasswordByUsername(entry);
            LOGGER.info("Validating response for trying to request password reset by invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User with username: '" + entry + "' not found"));
        }
        var nonExistingUsername = "NonExistingUser_" + DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to request password reset by non existing username: '{}'", nonExistingUsername);
        var response = UserSelfCallsHelper.forgotPasswordByUsername(nonExistingUsername);
        LOGGER.info("Validating response for trying to request password reset by non existing username: '{}'\n{}", nonExistingUsername, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User with username: '" + nonExistingUsername + "' not found"));
    }

    @Test
    public void test_ForgotPasswordByUsername_EmailNotVerified() {
        var user = DtosHelper.createRandomUserDto();
        user.setEmailVerified(false);
        createTestUser(user);
        LOGGER.info("Attempting to request password reset by username: '{}' when email is not verified", user.getUsername());
        var response = UserSelfCallsHelper.forgotPasswordByUsername(user.getUsername());
        LOGGER.info("Validating response for trying to request password reset by username: '{}' when email is not verified\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Registered email is not verified"));
    }

    @Test
    public void test_ForgotPasswordByEmail_Success() {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Attempting to request password reset by email: '{}'", user.getEmail());
        var response = UserSelfCallsHelper.forgotPasswordByEmail(user.getEmail());
        LOGGER.info("Validating response for successful password reset request by email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("OTP sent to your registered email for password reset"));
    }

    @Test
    public void test_ForgotPasswordByEmail_InvalidInputs() {
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to request password reset by invalid email: '{}'", entry);
            var response = UserSelfCallsHelper.forgotPasswordByEmail(entry);
            LOGGER.info("Validating response for trying to request password reset by invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User with email: '" + entry + "' not found"));
        }
        var nonExistingEmail = "nonexisting_" + DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric().toLowerCase() + "@example.com";
        LOGGER.info("Attempting to request password reset by non existing email: '{}'", nonExistingEmail);
        var response = UserSelfCallsHelper.forgotPasswordByEmail(nonExistingEmail);
        LOGGER.info("Validating response for trying to request password reset by non existing email: '{}'\n{}", nonExistingEmail, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User with email: '" + nonExistingEmail + "' not found"));
    }

    @Test
    public void test_ForgotPasswordByEmail_EmailNotVerified() {
        var user = DtosHelper.createRandomUserDto();
        user.setEmailVerified(false);
        createTestUser(user);
        LOGGER.info("Attempting to request password reset by email: '{}' when email is not verified", user.getEmail());
        var response = UserSelfCallsHelper.forgotPasswordByEmail(user.getEmail());
        LOGGER.info("Validating response for trying to request password reset by email: '{}' when email is not verified\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Registered email is not verified"));
    }

    @Test
    public void test_ForgotPassword_Success() {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Attempting to request password reset by username: '{}'", user.getUsername());
        var response = UserSelfCallsHelper.forgotPassword(user.getUsername());
        LOGGER.info("Validating response for successful password reset request by username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("OTP sent to your registered email for password reset"));
        LOGGER.info("Attempting to request password reset by email: '{}'", user.getEmail());
        response = UserSelfCallsHelper.forgotPassword(user.getEmail());
        LOGGER.info("Validating response for successful password reset request by email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("OTP sent to your registered email for password reset"));
    }

    @Test
    public void test_ForgotPassword_InvalidInputs() {
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to request password reset by invalid input(username/email): '{}'", entry);
            var response = UserSelfCallsHelper.forgotPassword(entry);
            LOGGER.info("Validating response for trying to request password reset by invalid input(username/email): '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("not found"));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to request password reset by invalid input(username/email): '{}'", entry);
            var response = UserSelfCallsHelper.forgotPassword(entry);
            LOGGER.info("Validating response for trying to request password reset by invalid input(username/email): '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("not found"));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to request password reset by non existing username: '{}'", uniqueString);
        var response = UserSelfCallsHelper.forgotPassword("NonExistingUser_" + uniqueString);
        LOGGER.info("Validating response for trying to request password reset by non existing username: '{}'\n{}", "NonExistingUser_" + uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("not found"));
        LOGGER.info("Attempting to request password reset by non existing email: '{}'", "user_" + uniqueString.toLowerCase() + "@example.com");
        response = UserSelfCallsHelper.forgotPassword("user_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Validating response for trying to request password reset by non existing email: '{}'\n{}", "user_" + uniqueString.toLowerCase() + "@example.com", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("not found"));
    }

    @Test
    public void test_ForgotPassword_EmailNotVerified() {
        var user = DtosHelper.createRandomUserDto();
        user.setEmailVerified(false);
        createTestUser(user);
        LOGGER.info("Attempting to request password reset by username: '{}' when email is not verified", user.getUsername());
        var response = UserSelfCallsHelper.forgotPassword(user.getUsername());
        LOGGER.info("Validating response for trying to request password reset by username: '{}' when email is not verified\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Registered email is not verified"));
        LOGGER.info("Attempting to request password reset by email: '{}' when email is not verified", user.getEmail());
        response = UserSelfCallsHelper.forgotPassword(user.getEmail());
        LOGGER.info("Validating response for trying to request password reset by email: '{}' when email is not verified\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Registered email is not verified"));
    }

    @Test
    public void test_ResetPasswordUsingUsername_Success() throws Exception {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Getting OTP for password reset by username: '{}'", user.getUsername());
        UserSelfCallsHelper.forgotPasswordByUsername(user.getUsername()).then().statusCode(200);
        LOGGER.info("Extracting OTP from email for password reset ...");
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "Otp for password reset using username");
        var resetPwdDto = ResetPwdDto.builder().username(user.getUsername()).password("Password@1").confirmPassword("Password@1").otp(otp).build();
        LOGGER.info("Attempting to reset password using username: '{}'\n{}", user.getUsername(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
        LOGGER.info("Validating response for successful password reset using username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Password reset successfully"));
        LOGGER.info("Validating that the password has been reset successfully by logging in with new password ...");
        AuthCallsHelper.login(user.getUsername(), resetPwdDto.getPassword()).then().statusCode(200);
    }

    @Test
    public void test_ResetPasswordUsingUsername_InvalidInputs() {
        var resetPwdDto = new ResetPwdDto();
        LOGGER.info("Attempting to reset password using username with null username:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using null username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            resetPwdDto.setUsername(entry);
            LOGGER.info("Attempting to reset password using invalid username: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password using invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        resetPwdDto.setUsername("AutoTestUser_" + uniqueString);
        LOGGER.info("Attempting to reset password using username with null password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using username with null password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            resetPwdDto.setPassword(entry);
            LOGGER.info("Attempting to reset password using username with invalid password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password using username with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        resetPwdDto.setPassword("ValidPassword123!_" + uniqueString);
        resetPwdDto.setConfirmPassword("DifferentPassword123!_" + uniqueString);
        LOGGER.info("Attempting to reset password using username with non matching confirm password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using username with non matching confirm password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        resetPwdDto.setConfirmPassword(resetPwdDto.getPassword());
        LOGGER.info("Attempting to reset password using username with null OTP:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using username with null OTP:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            resetPwdDto.setOtp(entry);
            LOGGER.info("Attempting to reset password using username with invalid OTP: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password using username with invalid OTP: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
    }

    @Test
    public void test_ResetPasswordUsingUsername_InvalidOtp() {
        var user = createTestUser();
        var resetPwdDto = ResetPwdDto.builder().username(user.getUsername()).password("Password@1").confirmPassword("Password@1").otp("123456").build();
        LOGGER.info("Attempting to reset password using username with invalid OTP: '{}'\n{}", user.getUsername(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPasswordUsingUsername(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using username with invalid OTP: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired OTP"));
    }

    @Test
    public void test_ResetPasswordUsingEmail_Success() throws Exception {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Getting OTP for password reset by email: '{}'", user.getEmail());
        UserSelfCallsHelper.forgotPasswordByEmail(user.getEmail()).then().statusCode(200);
        LOGGER.info("Extracting OTP from email for password reset ...");
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "Otp for password reset using email");
        var resetPwdDto = ResetPwdDto.builder().email(user.getEmail()).password("Password@1").confirmPassword("Password@1").otp(otp).build();
        LOGGER.info("Attempting to reset password using email: '{}'\n{}", user.getEmail(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
        LOGGER.info("Validating response for successful password reset using email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Password reset successfully"));
        LOGGER.info("Validating that the password has been reset successfully by logging in with new password ...");
        AuthCallsHelper.login(user.getUsername(), resetPwdDto.getPassword()).then().statusCode(200);
    }

    @Test
    public void test_ResetPasswordUsingEmail_InvalidInputs() {
        var resetPwdDto = new ResetPwdDto();
        LOGGER.info("Attempting to reset password using email with null email:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using null email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            resetPwdDto.setEmail(entry);
            LOGGER.info("Attempting to reset password using email with invalid email: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password using email with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        resetPwdDto.setEmail("AutoTestUser_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Attempting to reset password using email with null password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using email with null password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            resetPwdDto.setPassword(entry);
            LOGGER.info("Attempting to reset password using email with invalid password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password using email with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        resetPwdDto.setPassword("ValidPassword123!_" + uniqueString);
        resetPwdDto.setConfirmPassword("DifferentPassword123!_" + uniqueString);
        LOGGER.info("Attempting to reset password using email with non matching confirm password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using email with non matching confirm password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        resetPwdDto.setConfirmPassword(resetPwdDto.getPassword());
        LOGGER.info("Attempting to reset password using email with null OTP:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using email with null OTP:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            resetPwdDto.setOtp(entry);
            LOGGER.info("Attempting to reset password using email with invalid OTP: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password using email with invalid OTP: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
    }

    @Test
    public void test_ResetPasswordUsingEmail_InvalidOtp() {
        var user = createTestUser();
        var resetPwdDto = ResetPwdDto.builder().email(user.getEmail()).password("Password@1").confirmPassword("Password@1").otp("123456").build();
        LOGGER.info("Attempting to reset password using email with invalid OTP: '{}'\n{}", user.getEmail(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPasswordUsingEmail(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using email with invalid OTP: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired OTP"));
    }

    @Test
    public void test_ResetPassword_Success() throws Exception {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Getting OTP for password reset by username: '{}'", user.getUsername());
        UserSelfCallsHelper.forgotPassword(user.getUsername()).then().statusCode(200);
        LOGGER.info("Extracting OTP from email for password reset ...");
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "Otp for password reset using username");
        var resetPwdDto = ResetPwdDto.builder().usernameOrEmail(user.getUsername()).password("Password@1").confirmPassword("Password@1").otp(otp).build();
        LOGGER.info("Attempting to reset password using username: '{}'\n{}", user.getUsername(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPassword(resetPwdDto);
        LOGGER.info("Validating response for successful password reset using username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Password reset successfully"));
        LOGGER.info("Validating that the password has been reset successfully by logging in with new password ...");
        AuthCallsHelper.login(user.getUsername(), resetPwdDto.getPassword()).then().statusCode(200);
        LOGGER.info("Getting OTP for password reset by email: '{}'", user.getEmail());
        UserSelfCallsHelper.forgotPassword(user.getEmail()).then().statusCode(200);
        LOGGER.info("Extracting OTP from email for password reset ...");
        otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "Otp for password reset using email");
        resetPwdDto = ResetPwdDto.builder().usernameOrEmail(user.getEmail()).password("Password@2").confirmPassword("Password@2").otp(otp).build();
        LOGGER.info("Attempting to reset password using email: '{}'\n{}", user.getEmail(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPassword(resetPwdDto);
        LOGGER.info("Validating response for successful password reset using email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Password reset successfully"));
        LOGGER.info("Validating that the password has been reset successfully by logging in with new password ...");
        AuthCallsHelper.login(user.getUsername(), resetPwdDto.getPassword()).then().statusCode(200);
    }

    @Test
    public void test_ResetPassword_InvalidInputs() {
        var resetPwdDto = new ResetPwdDto();
        LOGGER.info("Attempting to reset password with null username/email:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPassword(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password with null username/email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            resetPwdDto.setUsernameOrEmail(entry);
            LOGGER.info("Attempting to reset password with invalid username/email: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPassword(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password with invalid username/email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            resetPwdDto.setUsernameOrEmail(entry);
            LOGGER.info("Attempting to reset password with invalid username/email: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPassword(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password with invalid username/email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        resetPwdDto.setUsernameOrEmail("AutoTestUser_" + uniqueString);
        LOGGER.info("Attempting to reset password with null password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPassword(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password with null password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            resetPwdDto.setPassword(entry);
            LOGGER.info("Attempting to reset password with invalid password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPassword(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        resetPwdDto.setPassword("ValidPassword123!_" + uniqueString);
        resetPwdDto.setConfirmPassword("DifferentPassword123!_" + uniqueString);
        LOGGER.info("Attempting to reset password with non matching confirm password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPassword(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password with non matching confirm password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        resetPwdDto.setConfirmPassword(resetPwdDto.getPassword());
        LOGGER.info("Attempting to reset password with null OTP:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPassword(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password with null OTP:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            resetPwdDto.setOtp(entry);
            LOGGER.info("Attempting to reset password with invalid OTP: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPassword(resetPwdDto);
            LOGGER.info("Validating response for trying to reset password with invalid OTP: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
    }

    @Test
    public void test_ResetPassword_InvalidOtp() {
        var user = createTestUser();
        var resetPwdDto = ResetPwdDto.builder().usernameOrEmail(user.getUsername()).password("Password@1").confirmPassword("Password@1").otp("123456").build();
        LOGGER.info("Attempting to reset password using invalid OTP for username: '{}'\n{}", user.getUsername(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPassword(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using invalid OTP for username: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired OTP"));
        resetPwdDto.setUsernameOrEmail(user.getEmail());
        LOGGER.info("Attempting to reset password using invalid OTP for email: '{}'\n{}", user.getEmail(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPassword(resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using invalid OTP for email: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired OTP"));
    }

    @Test
    public void test_ResetPasswordUsingOldPassword_Success() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        var resetPwdDto = ResetPwdDto.builder().oldPassword(user.getPassword()).newPassword("NewPassword@1").confirmPassword("NewPassword@1").build();
        LOGGER.info("Attempting to reset password using old password for user: '{}'\n{}", user.getUsername(), ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPasswordUsingOldPassword(accessToken, resetPwdDto);
        LOGGER.info("Validating response for successful password reset using old password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Password reset successfully"));
        LOGGER.info("Validating that the password has been reset successfully by logging in with new password ...");
        AuthCallsHelper.login(user.getUsername(), resetPwdDto.getNewPassword()).then().statusCode(200);
    }

    @Test
    public void test_ResetPasswordUsingOldPassword_InvalidInputs() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        var resetPwdDto = new ResetPwdDto();
        LOGGER.info("Attempting to reset password using old password with null old password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        var response = UserSelfCallsHelper.resetPasswordUsingOldPassword(accessToken, resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using old password with null old password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            resetPwdDto.setOldPassword(entry);
            LOGGER.info("Attempting to reset password using old password with invalid old password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPasswordUsingOldPassword(accessToken, resetPwdDto);
            LOGGER.info("Validating response for trying to reset password using old password with invalid old password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        resetPwdDto.setOldPassword("ValidOldPassword@1_" + uniqueString);
        LOGGER.info("Attempting to reset password using old password with null new password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingOldPassword(accessToken, resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using old password with null new password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            resetPwdDto.setNewPassword(entry);
            LOGGER.info("Attempting to reset password using old password with invalid new password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(resetPwdDto));
            response = UserSelfCallsHelper.resetPasswordUsingOldPassword(accessToken, resetPwdDto);
            LOGGER.info("Validating response for trying to reset password using old password with invalid new password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        resetPwdDto.setNewPassword("ValidNewPassword123!_" + uniqueString);
        resetPwdDto.setConfirmPassword("DifferentNewPassword123!_" + uniqueString);
        LOGGER.info("Attempting to reset password using old password with non matching confirm password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingOldPassword(accessToken, resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using old password with non matching confirm password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        resetPwdDto.setConfirmPassword(resetPwdDto.getNewPassword());
        resetPwdDto.setOldPassword("InvalidOldPassword@1" + uniqueString);
        LOGGER.info("Attempting to reset password using old password with invalid old password:\n{}", ToJsonForLoggingUtil.toJson(resetPwdDto));
        response = UserSelfCallsHelper.resetPasswordUsingOldPassword(accessToken, resetPwdDto);
        LOGGER.info("Validating response for trying to reset password using old password with invalid old password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Invalid old password"));
    }

    @Test
    public void test_EmailChangeRequest_Success() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to change email for user: '{}' New email: '{}'", user.getUsername(), TEST_EMAIL);
        var response = UserSelfCallsHelper.emailChangeRequest(accessToken, TEST_EMAIL);
        LOGGER.info("Validating response for successful email change request:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("OTP sent to your new email for email verification"));
    }

    @Test
    public void test_EmailChangeRequest_InvalidInputs() {
        var user = createTestUser();
        var user2 = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to change email for user: '{}' with invalid email: '{}'", user.getUsername(), entry);
            var response = UserSelfCallsHelper.emailChangeRequest(accessToken, entry);
            LOGGER.info("Validating response for trying to change email with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Email: '" + entry + "'"));
        }
        LOGGER.info("Attempting to change email for user: '{}' with old email: '{}'", user.getUsername(), user.getEmail());
        var response = UserSelfCallsHelper.emailChangeRequest(accessToken, user.getEmail());
        LOGGER.info("Validating response for trying to change email with old email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("New email: '" + user.getEmail() + "' is same as current email: '" + user.getEmail() + "'"));
        LOGGER.info("Attempting to change email for user: '{}' with a email already taken by another user: '{}'", user.getUsername(), user2.getEmail());
        response = UserSelfCallsHelper.emailChangeRequest(accessToken, user2.getEmail());
        LOGGER.info("Validating response for trying to change email with a email already taken by another user:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email: '" + user2.getEmail() + "' already taken"));
    }

    @Test
    public void test_VerifyEmailChange_Success() throws Exception {
        var user = createTestUser();
        try {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Requesting email change for user: '{}'", user.getUsername());
            UserSelfCallsHelper.emailChangeRequest(accessToken, TEST_EMAIL).then().statusCode(200);
            LOGGER.info("Extracting OTP from email for email change verification ...");
            var otp = EmailReaderUtil.getOtpFromEmail(TEST_EMAIL, TEST_EMAIL_PASSWORD, "Otp for email change verification");
            LOGGER.info("Attempting to verify email change for user: '{}'", user.getUsername());
            var response = UserSelfCallsHelper.verifyEmailChange(accessToken, otp, user.getPassword());
            LOGGER.info("Validating response for successful email change verification:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", containsString("Your email changed successfully to: '" + TEST_EMAIL + "'. Please login again to continue"))
                    .body("user.username", equalTo(user.getUsername()))
                    .body("user.email", equalTo(TEST_EMAIL));
            LOGGER.info("Fetching user details to verify email change of user: '{}'", user.getUsername());
            response = CallsUsingGlobalAdminUserHelper.getUser(user.getUsername());
            LOGGER.info("Validating response for fetching user details after email change:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200).body("email", equalTo(TEST_EMAIL));
        } finally {
            CleanUpHelper.cleanUpTestUsers(user);
        }
    }

    @Test
    public void test_VerifyEmailChange_InvalidInputs() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            LOGGER.info("Attempting to verify email change with invalid OTP: '{}'", entry);
            var response = UserSelfCallsHelper.verifyEmailChange(accessToken, entry, user.getPassword());
            LOGGER.info("Validating response for trying to verify email change with invalid OTP: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid otp or password"));
        }
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to verify email change with invalid password: '{}'", entry);
            var response = UserSelfCallsHelper.verifyEmailChange(accessToken, "123456", entry);
            LOGGER.info("Validating response for trying to verify email change with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid otp or password"));
        }
        LOGGER.info("Attempting to verify email change with invalid OTP: '123456'");
        var response = UserSelfCallsHelper.verifyEmailChange(accessToken, "123456", user.getPassword());
        LOGGER.info("Validating response for trying to verify email change with invalid OTP: '123456'\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Expired otp"));
    }

    @Test
    public void test_GetYourSelf() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to fetch your self details for user: '{}'", user.getUsername());
        var response = UserSelfCallsHelper.getYourself(accessToken);
        LOGGER.info("Validating response for fetching your self details:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("username", equalTo(user.getUsername())).body("email", equalTo(user.getEmail()));
    }

    @Test
    public void test_DeleteAccountByPassword_Success() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to delete account by password for user: '{}'", user.getUsername());
        var response = UserSelfCallsHelper.deleteAccountByPassword(accessToken, user.getPassword());
        LOGGER.info("Validating response for successful account deletion:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Account deleted successfully"));
        LOGGER.info("Fetching user details after account deletion for user: '{}'", user.getUsername());
        response = CallsUsingGlobalAdminUserHelper.getUser(user.getUsername());
        LOGGER.info("Validating response for fetching user details after account deletion:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400);
    }

    @Test
    public void test_DeleteAccountByPassword_InvalidInputs() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to delete account by password with invalid password: '{}'", entry);
            var response = UserSelfCallsHelper.deleteAccountByPassword(accessToken, entry);
            LOGGER.info("Validating response for trying to delete account by password with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid password"));
        }
        LOGGER.info("Attempting to delete account by password with invalid password: '{}'", "InvalidPassword@1" + user.getPassword());
        var response = UserSelfCallsHelper.deleteAccountByPassword(accessToken, "InvalidPassword@1" + user.getPassword());
        LOGGER.info("Validating response for trying to delete account by password with invalid password: '{}'\n{}", "InvalidPassword@1" + user.getPassword(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Invalid password"));
        LOGGER.info("Enabling Auth App MFA for user: '{}'", user.getUsername());
        response = MfaCallsHelper.generateQRCodeForAuthApp(accessToken);
        response.then().statusCode(200);
        var secret = QRUtil.extractSecretFromQRImage(response.asByteArray());
        MfaCallsHelper.verifyTotpToSetupAuthApp(accessToken, TOTPUtil.generateCode(secret)).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        response = MfaCallsHelper.verifyAuthAppOtp(TOTPUtil.generateCode(secret), stateToken);
        response.then().statusCode(200);
        LOGGER.info("Attempting to delete account by password when MFA is enabled for user: '{}'", user.getUsername());
        response = UserSelfCallsHelper.deleteAccountByPassword(response.jsonPath().getString("access_token"), user.getPassword());
        LOGGER.info("Validating response for trying to delete account by password when MFA is enabled:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("You cannot delete your mfa enabled account using password only"));
    }

    @Test
    public void test_SendEmailOtpToDeleteAccount_Success() throws Exception {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Enabling email mfa of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken).then().statusCode(200);
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "OTP to verify Email MFA");
        var response = MfaCallsHelper.verifyEmailOtp(otp, stateToken);
        response.then().statusCode(200);
        LOGGER.info("Attempting to send email OTP to delete account for user: '{}'", user.getUsername());
        response = UserSelfCallsHelper.sendEmailOtpToDeleteAccount(response.jsonPath().getString("access_token"));
        LOGGER.info("Validating response for successful email OTP to delete account:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("OTP sent to your registered email for account deletion verification"));
    }

    @Test
    public void test_SendEmailOtpToDeleteAccount_InvalidInputs() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to send email OTP to delete account for user: '{}' when email MFA is not enabled", user.getUsername());
        var response = UserSelfCallsHelper.sendEmailOtpToDeleteAccount(accessToken);
        LOGGER.info("Validating response for trying to send email OTP to delete account when email MFA is not enabled:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email Mfa is not enabled"));
    }

    @Test
    public void test_VerifyEmailOtpToDeleteAccount_Success() throws Exception {
        var user = createTestUserRandomValidEmail();
        LOGGER.info("Enabling email mfa of user: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        var stateToken = AuthCallsHelper.getStateToken(user.getUsername(), user.getPassword());
        MfaCallsHelper.sendOtpToVerifyEmailMfa(stateToken).then().statusCode(200);
        var otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "OTP to verify Email MFA");
        var response = MfaCallsHelper.verifyEmailOtp(otp, stateToken);
        response.then().statusCode(200);
        LOGGER.info("Requesting email otp to delete account for user: '{}'", user.getUsername());
        var accessToken = response.jsonPath().getString("access_token");
        UserSelfCallsHelper.sendEmailOtpToDeleteAccount(accessToken).then().statusCode(200);
        LOGGER.info("Extracting otp from email for account deletion ...");
        otp = EmailReaderUtil.getOtpFromEmail(user.getEmail(), TEST_EMAIL_PASSWORD, "Otp for account deletion email mfa");
        LOGGER.info("Attempting to verify email OTP to delete account for user: '{}'", user.getUsername());
        response = UserSelfCallsHelper.verifyEmailOtpToDeleteAccount(accessToken, user.getPassword(), otp);
        LOGGER.info("Validating response for successful email OTP to delete account:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Account deleted successfully"));
        LOGGER.info("Fetching user details after account deletion for user: '{}'", user.getUsername());
        response = CallsUsingGlobalAdminUserHelper.getUser(user.getUsername());
        LOGGER.info("Validating response for fetching user details after account deletion:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found"));
    }

    @Test
    public void test_VerifyEmailOtpToDeleteAccount_InvalidInputs() throws Exception {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to verify email OTP to delete account with invalid password: '{}'", entry);
            var response = UserSelfCallsHelper.verifyEmailOtpToDeleteAccount(accessToken, entry, "123456");
            LOGGER.info("Validating response for trying to verify email OTP to delete account with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid password or otp"));
        }
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            LOGGER.info("Attempting to verify email OTP to delete account with invalid OTP: '{}'", entry);
            var response = UserSelfCallsHelper.verifyEmailOtpToDeleteAccount(accessToken, user.getPassword(), entry);
            LOGGER.info("Validating response for trying to verify email OTP to delete account with invalid OTP: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid password or otp"));
        }
        LOGGER.info("Attempting to verify email OTP when email MFA is not enabled for user: '{}'", user.getUsername());
        var response = UserSelfCallsHelper.verifyEmailOtpToDeleteAccount(accessToken, user.getPassword(), "123456");
        LOGGER.info("Validating response for trying to verify email OTP when email MFA is not enabled:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email Mfa is not enabled"));
    }

    @Test
    public void test_DeleteAccountByAuthAppTotp_Success() throws NotFoundException, IOException, InvalidKeyException {
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
        LOGGER.info("Attempting to delete account by Auth App TOTP for user: '{}'", user.getUsername());
        response = UserSelfCallsHelper.deleteAccountByAuthAppTotp(accessToken, user.getPassword(), TOTPUtil.generateCode(secret));
        LOGGER.info("Validating response for successful account deletion by Auth App TOTP:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Account deleted successfully"));
        LOGGER.info("Fetching user details after account deletion for user: '{}'", user.getUsername());
        response = CallsUsingGlobalAdminUserHelper.getUser(user.getUsername());
        LOGGER.info("Validating response for fetching user details after account deletion:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found"));
    }

    @Test
    public void test_DeleteAccountByAuthAppTotp_InvalidInputs() throws NotFoundException, IOException, InvalidKeyException {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to delete account by Auth App TOTP with invalid password: '{}'", entry);
            var response = UserSelfCallsHelper.deleteAccountByAuthAppTotp(accessToken, entry, "123456");
            LOGGER.info("Validating response for trying to delete account by Auth App TOTP with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid password or TOTP"));
        }
        for (var entry : InvalidInputsHelper.invalidOTPs()) {
            LOGGER.info("Attempting to delete account by Auth App TOTP with invalid OTP: '{}'", entry);
            var response = UserSelfCallsHelper.deleteAccountByAuthAppTotp(accessToken, user.getPassword(), entry);
            LOGGER.info("Validating response for trying to delete account by Auth App TOTP with invalid OTP: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid password or TOTP"));
        }
        LOGGER.info("Attempting to delete account by Auth App TOTP when Auth App MFA is not enabled for user: '{}'", user.getUsername());
        var response = UserSelfCallsHelper.deleteAccountByAuthAppTotp(accessToken, user.getPassword(), "123456");
        LOGGER.info("Validating response for trying to delete account by Auth App TOTP when Auth App MFA is not enabled:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Authenticator App Mfa is not enabled"));
    }

    @Test
    public void test_UpdateYourselfBasic_Success() {
        var user = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        var userSelfUpdationDto = UserSelfUpdationDto.builder()
                .firstName("UpdatedFirstName")
                .middleName("UpdatedMiddleName")
                .lastName("UpdatedLastName")
                .oldPassword(user.getPassword())
                .username("Updated_" + user.getUsername())
                .newPassword("UpdatedPassword@1")
                .confirmNewPassword("UpdatedPassword@1")
                .build();
        LOGGER.info("Attempting to update yourself with new details:\n{}", ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
        var response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
        LOGGER.info("Validating response for successful user self updation:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("firstName", equalTo(userSelfUpdationDto.getFirstName()))
                .body("middleName", equalTo(userSelfUpdationDto.getMiddleName()))
                .body("lastName", equalTo(userSelfUpdationDto.getLastName()))
                .body("username", equalTo(userSelfUpdationDto.getUsername()));
        LOGGER.info("Validating that the password is updated successfully by logging in with new password ...");
        AuthCallsHelper.login(userSelfUpdationDto.getUsername(), userSelfUpdationDto.getNewPassword()).then().statusCode(200);
        user.setUsername(userSelfUpdationDto.getUsername());
    }

    @Test
    public void test_UpdateYourselfBasic_InvalidInputs() {
        var user = DtosHelper.createRandomUserDto();
        var user2 = DtosHelper.createRandomUserDto();
        createTestUsers(Set.of(user, user2));
        var userSelfUpdationDto = new UserSelfUpdationDto();
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidNames()) {
            userSelfUpdationDto.setFirstName(entry);
            LOGGER.info("Attempting to update yourself with invalid first name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
            var response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
            LOGGER.info("Validating response for trying to update yourself with invalid first name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        userSelfUpdationDto.setFirstName("UpdatedFirstName");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            userSelfUpdationDto.setMiddleName(entry);
            LOGGER.info("Attempting to update yourself with invalid middle name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
            var response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
            LOGGER.info("Validating response for trying to update yourself with invalid middle name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        userSelfUpdationDto.setMiddleName("UpdatedMiddleName");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            userSelfUpdationDto.setLastName(entry);
            LOGGER.info("Attempting to update yourself with invalid last name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
            var response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
            LOGGER.info("Validating response for trying to update yourself with invalid last name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        userSelfUpdationDto.setLastName("UpdatedLastName");
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            userSelfUpdationDto.setUsername(entry);
            LOGGER.info("Attempting to update yourself with invalid username: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
            var response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
            LOGGER.info("Validating response for trying to update yourself with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        userSelfUpdationDto.setUsername("Updated_" + user.getUsername());
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            userSelfUpdationDto.setNewPassword(entry);
            userSelfUpdationDto.setConfirmNewPassword(entry);
            LOGGER.info("Attempting to update yourself with invalid new password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
            var response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
            LOGGER.info("Validating response for trying to update yourself with invalid new password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        userSelfUpdationDto.setNewPassword("UpdatedPassword@1");
        userSelfUpdationDto.setConfirmNewPassword("DifferentUpdatedPassword@1");
        LOGGER.info("Attempting to update yourself with non matching confirm new password:\n{}", ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
        var response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
        LOGGER.info("Validating response for trying to update yourself with non matching confirm new password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        userSelfUpdationDto.setConfirmNewPassword(userSelfUpdationDto.getNewPassword());
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            userSelfUpdationDto.setOldPassword(entry);
            LOGGER.info("Attempting to update yourself with invalid old password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
            response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
            LOGGER.info("Validating response for trying to update yourself with invalid old password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        userSelfUpdationDto.setOldPassword("InvalidOldPassword@1" + user.getPassword());
        LOGGER.info("Attempting to update yourself with invalid old password:\n{}", ToJsonForLoggingUtil.toJson(userSelfUpdationDto));
        response = UserSelfCallsHelper.updateYourselfBasic(accessToken, userSelfUpdationDto);
        LOGGER.info("Validating response for trying to update yourself with invalid old password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
    }
}