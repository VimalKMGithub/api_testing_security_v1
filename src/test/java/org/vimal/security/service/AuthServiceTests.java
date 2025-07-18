package org.vimal.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;
import org.vimal.security.BaseTest;
import org.vimal.security.helper.AuthCallsHelper;
import org.vimal.security.helper.CallsUsingGlobalAdminUserHelper;
import org.vimal.security.helper.InvalidInputsHelper;
import org.vimal.security.util.DateTimeUtil;
import org.vimal.security.util.RandomStringUtil;

import java.util.UUID;

import static org.hamcrest.Matchers.*;

public class AuthServiceTests extends BaseTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthServiceTests.class);

    @Test
    public void test_LoginByUsername_Success() {
        var user = createTestUser();
        LOGGER.info("Attempting to login by username: '{}'", user.getUsername());
        var response = AuthCallsHelper.loginByUsername(user.getUsername(), user.getPassword());
        LOGGER.info("Validating response for login by username: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .body("expires_in_seconds", equalTo(1800))
                .body("token_type", containsString("Bearer"));
    }

    @Test
    public void test_LoginByUsername_InvalidInputs() {
        var password = "ValidPassword123!";
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to login by invalid username: '{}'", entry);
            var response = AuthCallsHelper.loginByUsername(entry, password);
            LOGGER.info("Validating response for login by invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Invalid credentials"));
        }
        var username = "validUsername";
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to login by username with invalid password: '{}'", entry);
            var response = AuthCallsHelper.loginByUsername(username, entry);
            LOGGER.info("Validating response for login by username with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Invalid credentials"));
        }
        var nonExistingUsername = "NonExistingUsername_" + DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to login by non-existing username: '{}'", nonExistingUsername);
        var response = AuthCallsHelper.loginByUsername(nonExistingUsername, "SomePassword123!");
        LOGGER.info("Validating response for login by non-existing username: '{}'\n{}", nonExistingUsername, response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Invalid credentials"));
    }

    @Test
    public void test_LoginByUsername_AccLockedAfterMaxFailedLoginAttempts() {
        var user = createTestUser();
        LOGGER.info("Simulating failed login attempts by username: '{}'", user.getUsername());
        for (var i = 1; i <= 5; i++) {
            LOGGER.info("Attempt '{}': Trying to login by username with wrong password: '{}'", i, user.getUsername());
            var response = AuthCallsHelper.loginByUsername(user.getUsername(), "WrongPassword!1");
            LOGGER.info("Validating response for failed login attempt '{}' by username: '{}'\n{}", i, user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Bad credentials"));
        }
        LOGGER.info("Attempting to login by username after max failed attempts: '{}'", user.getUsername());
        var response = AuthCallsHelper.loginByUsername(user.getUsername(), user.getPassword());
        LOGGER.info("Validating response for login by username after max failed attempts: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Account is temporarily locked. Please try again later."));

    }

    @Test
    public void test_LoginByUsername_GetStateTokenWhenMfaIsEnabled() {
        var user = createTestUser();
        LOGGER.info("Enabling email MFA of user with username: '{}'", user.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        LOGGER.info("Attempting to login by username after enabling email MFA: '{}'", user.getUsername());
        var response = AuthCallsHelper.loginByUsername(user.getUsername(), user.getPassword());
        LOGGER.info("Validating response for login by username after enabling email MFA: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("message", containsString("MFA required"))
                .body("state_token", notNullValue());
    }

    @Test
    public void test_LoginByEmail_Success() {
        var user = createTestUser();
        LOGGER.info("Attempting to login by email: '{}'", user.getEmail());
        var response = AuthCallsHelper.loginByEmail(user.getEmail(), user.getPassword());
        LOGGER.info("Validating response for login email: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .body("expires_in_seconds", equalTo(1800))
                .body("token_type", containsString("Bearer"));
    }

    @Test
    public void test_LoginByEmail_InvalidInputs() {
        var password = "ValidPassword123!";
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to login by invalid email: '{}'", entry);
            var response = AuthCallsHelper.loginByEmail(entry, password);
            LOGGER.info("Validating response for login by invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Invalid credentials"));
        }
        var email = "user@example.com";
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to login by email with invalid password: '{}'", entry);
            var response = AuthCallsHelper.loginByEmail(email, entry);
            LOGGER.info("Validating response for login by email with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Invalid credentials"));
        }
        var nonExistingEmail = "nonexistingemail_" + DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric() + "@example.com";
        LOGGER.info("Attempting to login by non-existing email: '{}'", nonExistingEmail);
        var response = AuthCallsHelper.loginByEmail(nonExistingEmail, "SomePassword123!");
        LOGGER.info("Validating response for login by non-existing email: '{}'\n{}", nonExistingEmail, response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Invalid credentials"));
    }

    @Test
    public void test_LoginByEmail_AccLockedAfterMaxFailedLoginAttempts() {
        var user = createTestUser();
        LOGGER.info("Simulating failed login attempts by login by email: '{}'", user.getEmail());
        for (var i = 1; i <= 5; i++) {
            LOGGER.info("Attempt '{}': Trying to login by email with wrong password: '{}'", i, user.getEmail());
            var response = AuthCallsHelper.loginByEmail(user.getEmail(), "WrongPassword!1");
            LOGGER.info("Validating response for failed login attempt '{}' by email: '{}'\n{}", i, user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Bad credentials"));
        }
        LOGGER.info("Attempting to login by email after max failed attempts: '{}'", user.getEmail());
        var response = AuthCallsHelper.loginByEmail(user.getEmail(), user.getPassword());
        LOGGER.info("Validating response for login by email after max failed attempts: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Account is temporarily locked. Please try again later."));
    }

    @Test
    public void test_LoginByEmail_GetStateTokenWhenMfaIsEnabled() {
        var user = createTestUser();
        LOGGER.info("Enabling email MFA of user with email: '{}'", user.getEmail());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getEmail()).then().statusCode(200);
        LOGGER.info("Attempting to login by email after enabling email MFA: '{}'", user.getEmail());
        var response = AuthCallsHelper.loginByEmail(user.getEmail(), user.getPassword());
        LOGGER.info("Validating response for login by email after enabling email MFA: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("message", containsString("MFA required"))
                .body("state_token", notNullValue());
    }

    @Test
    public void test_Login_Success() {
        var user = createTestUser();
        LOGGER.info("Attempting to login with username: '{}'", user.getUsername());
        var response = AuthCallsHelper.login(user.getUsername(), user.getPassword());
        LOGGER.info("Validating response for login with username: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .body("expires_in_seconds", equalTo(1800))
                .body("token_type", containsString("Bearer"));
        LOGGER.info("Attempting to login with email: '{}'", user.getEmail());
        response = AuthCallsHelper.login(user.getEmail(), user.getPassword());
        LOGGER.info("Validating response for login with email: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .body("expires_in_seconds", equalTo(1800))
                .body("token_type", containsString("Bearer"));
    }

    @Test
    public void test_Login_InvalidInputs() {
        var password = "ValidPassword123!";
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to login with invalid username: '{}'", entry);
            var response = AuthCallsHelper.login(entry, password);
            LOGGER.info("Validating response for login with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Invalid credentials"));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to login with invalid email: '{}'", entry);
            var response = AuthCallsHelper.login(entry, password);
            LOGGER.info("Validating response for login with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Invalid credentials"));
        }
        var usernameOrEmail = "validUserOrEmail";
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            LOGGER.info("Attempting to login with valid input(username/email) with invalid password: '{}'", entry);
            var response = AuthCallsHelper.login(usernameOrEmail, entry);
            LOGGER.info("Validating response for login with valid input(username/email) with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Invalid credentials"));
        }
        var uniqueString = "user_" + DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to login with non-existing username: '{}'", uniqueString);
        var response = AuthCallsHelper.login(uniqueString, "SomePassword123!");
        LOGGER.info("Validating response for login with non-existing username: '{}'\n{}", uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Invalid credentials"));
        LOGGER.info("Attempting to login with non-existing email: '{}'", uniqueString + "@example.com");
        response = AuthCallsHelper.login(uniqueString + "@example.com", "SomePassword123!");
        LOGGER.info("Validating response for login with non-existing email: '{}'\n{}", uniqueString + "@example.com", response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Invalid credentials"));
    }

    @Test
    public void test_Login_AccLockedAfterMaxFailedLoginAttempts() {
        var user = createTestUser();
        LOGGER.info("Simulating failed login attempts with username/email: '{}'/'{}'", user.getUsername(), user.getEmail());
        for (var i = 1; i <= 5; i++) {
            LOGGER.info("Attempt '{}': Trying to login with {} with wrong password: '{}'", i + 1, (i % 2 == 0 ? "username" : "email"), (i % 2 == 0 ? user.getUsername() : user.getEmail()));
            var response = AuthCallsHelper.login(i % 2 == 0 ? user.getUsername() : user.getEmail(), "WrongPassword!1");
            LOGGER.info("Validating response for failed login attempt '{}' with {}: '{}'\n{}", i, (i % 2 == 0 ? "username" : "email"), (i % 2 == 0 ? user.getUsername() : user.getEmail()), response.getBody().asPrettyString());
            response.then().statusCode(401).body("message", containsString("Bad credentials"));
        }
        LOGGER.info("Attempting to login with username after max failed attempts: '{}'", user.getUsername());
        var response = AuthCallsHelper.login(user.getUsername(), user.getPassword());
        LOGGER.info("Validating response for login with username after max failed attempts: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Account is temporarily locked. Please try again later."));
        LOGGER.info("Attempting to login with email after max failed attempts: '{}'", user.getEmail());
        response = AuthCallsHelper.login(user.getEmail(), user.getPassword());
        LOGGER.info("Validating response for login with email after max failed attempts: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Account is temporarily locked. Please try again later."));
    }

    @Test
    public void test_Login_GetStateTokenWhenMfaIsEnabled() {
        var user = createTestUser();
        LOGGER.info("Enabling email MFA of user with username/email: '{}'/'{}'", user.getUsername(), user.getEmail());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(user.getUsername()).then().statusCode(200);
        LOGGER.info("Attempting to login with username after enabling email MFA: '{}'", user.getUsername());
        var response = AuthCallsHelper.login(user.getUsername(), user.getPassword());
        LOGGER.info("Validating response for login with username after enabling email MFA: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("message", containsString("MFA required"))
                .body("state_token", notNullValue());
        LOGGER.info("Attempting to login with email after enabling email MFA: '{}'", user.getEmail());
        response = AuthCallsHelper.login(user.getEmail(), user.getPassword());
        LOGGER.info("Validating response for login with email after enabling email MFA: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("message", containsString("MFA required"))
                .body("state_token", notNullValue());
    }

    @Test
    public void test_Logout() {
        var user = createTestUser();
        LOGGER.info("Attempting to log in with username: '{}'", user.getUsername());
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to log out after successful login with username: '{}'", user.getUsername());
        var response = AuthCallsHelper.logout(accessToken);
        LOGGER.info("Validating response for logout after successful login with username: '{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Logout successful"));
        LOGGER.info("Attempting to log out again with the same access token to verify that access token is invalidated after logout ...");
        response = AuthCallsHelper.logout(accessToken);
        LOGGER.info("Validating response for logout with invalidated access token:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Invalid token"));
        LOGGER.info("Attempting to log in again with email: '{}'", user.getEmail());
        accessToken = AuthCallsHelper.getAccessToken(user.getEmail(), user.getPassword());
        LOGGER.info("Attempting to log out after successful login with email: '{}'", user.getEmail());
        response = AuthCallsHelper.logout(accessToken);
        LOGGER.info("Validating response for logout after successful login with email: '{}'\n{}", user.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Logout successful"));
        LOGGER.info("Attempting to log out again with the same access token to verify that access token is invalidated after logout ...");
        response = AuthCallsHelper.logout(accessToken);
        LOGGER.info("Validating response for logout with invalidated access token:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Invalid token"));
    }

    @Test
    public void test_RefreshAccessToken_Success() {
        var user = createTestUser();
        LOGGER.info("Attempting to get refresh token for user: '{}'", user.getUsername());
        var refreshToken = AuthCallsHelper.getRefreshToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to refresh access token using refresh token: '{}'", refreshToken);
        var response = AuthCallsHelper.refreshAccessToken(refreshToken);
        LOGGER.info("Validating response for refreshing access token using refresh token: '{}'\n{}", refreshToken, response.getBody().asPrettyString());
        response.then().statusCode(200)
                .body("access_token", notNullValue())
                .body("expires_in_seconds", equalTo(1800))
                .body("token_type", containsString("Bearer"));
    }

    @Test
    public void test_RefreshAccessToken_Failure() {
        var uuid = UUID.randomUUID().toString();
        LOGGER.info("Attempting to refresh access token using non-existing refresh token: '{}'", uuid);
        var response = AuthCallsHelper.refreshAccessToken(uuid);
        LOGGER.info("Validating response for refreshing access token using non-existing refresh token: '{}'\n{}", uuid, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Invalid or expired refresh token"));
        for (var entry : InvalidInputsHelper.invalidUuids()) {
            LOGGER.info("Attempting to refresh access token using invalid refresh token: '{}'", entry);
            response = AuthCallsHelper.refreshAccessToken(entry);
            LOGGER.info("Validating response for refreshing access token using invalid refresh token: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid refresh token"));
        }
    }

    @Test
    public void test_RevokeAccessToken() {
        var user = createTestUser();
        LOGGER.info("Attempting to get access token for user: '{}'", user.getUsername());
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to revoke access token: '{}'", accessToken);
        var response = AuthCallsHelper.revokeAccessToken(accessToken);
        LOGGER.info("Validating response for revoking access token: '{}'\n{}", accessToken, response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Access token revoked successfully"));
        LOGGER.info("Attempting to use revoked access token to verify that access token is invalidated after revocation ...");
        response = AuthCallsHelper.logout(accessToken);
        LOGGER.info("Validating response for using revoked access token:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(401).body("message", containsString("Invalid token"));
    }

    @Test
    public void test_RevokeRefreshToken_Success() {
        var user = createTestUser();
        LOGGER.info("Attempting to get refresh token for user: '{}'", user.getUsername());
        var refreshToken = AuthCallsHelper.getRefreshToken(user.getUsername(), user.getPassword());
        LOGGER.info("Attempting to revoke refresh token: '{}'", refreshToken);
        var response = AuthCallsHelper.revokeRefreshToken(refreshToken);
        LOGGER.info("Validating response for revoking refresh token: '{}'\n{}", refreshToken, response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Refresh token revoked successfully"));
        LOGGER.info("Attempting to use revoked refresh token to verify that refresh token is invalidated after revocation ...");
        response = AuthCallsHelper.refreshAccessToken(refreshToken);
        LOGGER.info("Validating response for using revoked refresh token:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Invalid or expired refresh token"));
    }

    @Test
    public void test_RevokeRefreshToken_Failure() {
        var uuid = UUID.randomUUID().toString();
        LOGGER.info("Attempting to revoke non-existing refresh token: '{}'", uuid);
        var response = AuthCallsHelper.revokeRefreshToken(uuid);
        LOGGER.info("Validating response for revoking non-existing refresh token: '{}'\n{}", uuid, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Invalid or expired refresh token"));
        for (var entry : InvalidInputsHelper.invalidUuids()) {
            LOGGER.info("Attempting to revoke invalid refresh token: '{}'", entry);
            response = AuthCallsHelper.revokeRefreshToken(entry);
            LOGGER.info("Validating response for revoking invalid refresh token: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Invalid refresh token"));
        }
    }
}