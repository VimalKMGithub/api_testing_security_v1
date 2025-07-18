package org.vimal.security;

import io.restassured.RestAssured;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.vimal.security.dto.RoleDto;
import org.vimal.security.dto.UserDto;
import org.vimal.security.helper.*;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public abstract class BaseTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(BaseTest.class);

    private static final String BASE_URL = "http://localhost:8080";
    private static final String BASE_PATH = "/api/v1";

    public static final String TEST_EMAIL = System.getenv("TEST_EMAIL");
    public static final String TEST_EMAIL_PASSWORD = System.getenv("TEST_EMAIL_PASSWORD");
    protected static final Set<Object> TEST_USERS = ConcurrentHashMap.newKeySet();
    protected static final Set<Object> TEST_ROLES = ConcurrentHashMap.newKeySet();

    public static final String GLOBAL_ADMIN_USERNAME = System.getenv("GLOBAL_ADMIN_USERNAME");
    public static final String GLOBAL_ADMIN_PASSWORD = System.getenv("GLOBAL_ADMIN_PASSWORD");
    public static String GLOBAL_ADMIN_ACCESS_TOKEN;

    @BeforeSuite
    public void setupBeforeSuite() {
        LOGGER.info("Setting up RestAssured with base URI: '{}', base path: '{}'", BASE_URL, BASE_PATH);
        RestAssured.baseURI = BASE_URL;
        RestAssured.basePath = BASE_PATH;
        LOGGER.info("Enabling logging of request and response if validation fails ...");
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        GLOBAL_ADMIN_ACCESS_TOKEN = AuthCallsHelper.getAccessToken(GLOBAL_ADMIN_USERNAME, GLOBAL_ADMIN_PASSWORD);
    }

    @AfterSuite
    public void cleanupAfterSuite() {
        LOGGER.info("Cleaning up environment after all tests ...");
        if (!TEST_USERS.isEmpty()) {
            LOGGER.info("Deleting test users ...");
            CleanUpHelper.cleanUpTestUsers(TEST_USERS);
            TEST_USERS.clear();
        }
        if (!TEST_ROLES.isEmpty()) {
            LOGGER.info("Deleting test roles ...");
            CleanUpHelper.cleanUpTestRoles(TEST_ROLES);
            TEST_ROLES.clear();
        }
        try {
            AuthCallsHelper.logout(GLOBAL_ADMIN_ACCESS_TOKEN);
        } catch (Exception ignored) {
        }
        LOGGER.info("Cleanup completed.");
    }

    protected static UserDto createTestUser() {
        return createTestUser(DtosHelper.createRandomUserDto());
    }

    protected static UserDto createTestUserRandomValidEmail() {
        return createTestUser(DtosHelper.createRandomUserDtoWithRandomValidEmail());
    }

    protected static UserDto createTestUser(Set<String> roles) {
        return createTestUser(DtosHelper.createRandomUserDto(roles));
    }

    protected static UserDto createTestUser(UserDto user) {
        LOGGER.info("Creating test user ...");
        var response = CallsUsingGlobalAdminUserHelper.createUsers(Set.of(user));
        response.then().statusCode(200);
        LOGGER.info("Created test user:\n{}", response.getBody().asPrettyString());
        TEST_USERS.add(user);
        return user;
    }

    protected static void createTestUsers(Set<UserDto> users) {
        LOGGER.info("Creating test users ...");
        var iterator = users.iterator();
        while (iterator.hasNext()) {
            var batch = new HashSet<UserDto>();
            while (iterator.hasNext() && batch.size() < CommonConstantsHelper.MAX_BATCH_SIZE) {
                batch.add(iterator.next());
            }
            var response = CallsUsingGlobalAdminUserHelper.createUsers(batch);
            response.then().statusCode(200);
            LOGGER.info("Created test users:\n{}", response.getBody().asPrettyString());
            TEST_USERS.addAll(batch);
        }
    }

    protected static RoleDto createTestRole() {
        return createTestRole(DtosHelper.createRandomRoleDto());
    }

    protected static RoleDto createTestRole(RoleDto role) {
        LOGGER.info("Creating test role ...");
        var response = CallsUsingGlobalAdminUserHelper.createRoles(Set.of(role));
        response.then().statusCode(200);
        LOGGER.info("Created test role:\n{}", response.getBody().asPrettyString());
        TEST_ROLES.add(role);
        return role;
    }

    protected static Set<RoleDto> createTestRoles(int count) {
        return createTestRoles(DtosHelper.createRandomRoleDtos(count));
    }

    protected static Set<RoleDto> createTestRoles(Set<RoleDto> roles) {
        LOGGER.info("Creating test roles ...");
        var iterator = roles.iterator();
        while (iterator.hasNext()) {
            var batch = new HashSet<RoleDto>();
            while (iterator.hasNext() && batch.size() < CommonConstantsHelper.MAX_BATCH_SIZE) {
                batch.add(iterator.next());
            }
            var response = CallsUsingGlobalAdminUserHelper.createRoles(batch);
            response.then().statusCode(200);
            LOGGER.info("Created test roles:\n{}", response.getBody().asPrettyString());
            TEST_ROLES.addAll(batch);
        }
        return roles;
    }
}