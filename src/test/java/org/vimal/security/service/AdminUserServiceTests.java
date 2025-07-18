package org.vimal.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;
import org.vimal.security.BaseTest;
import org.vimal.security.dto.RoleDto;
import org.vimal.security.dto.UserDto;
import org.vimal.security.enums.MfaMethods;
import org.vimal.security.enums.Permissions;
import org.vimal.security.enums.Roles;
import org.vimal.security.helper.*;
import org.vimal.security.util.DateTimeUtil;
import org.vimal.security.util.RandomStringUtil;
import org.vimal.security.util.ToJsonForLoggingUtil;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.*;

public class AdminUserServiceTests extends BaseTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AdminUserServiceTests.class);

    private Set<String> usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users() {
        var rolesSet = new HashSet<String>();
        rolesSet.add(Roles.ROLE_MANAGE_ROLES.name());
        rolesSet.add(Roles.ROLE_MANAGE_PERMISSIONS.name());
        return rolesSet;
    }

    private Set<String> rolesSetForAdmin_CreateUpdateDelete_Users() {
        var rolesSet = usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users();
        rolesSet.add(Roles.ROLE_MANAGE_USERS.name());
        return rolesSet;
    }

    private Set<String> rolesSetForSuperAdmin_CreateUpdateDelete_Users() {
        var rolesSet = rolesSetForAdmin_CreateUpdateDelete_Users();
        rolesSet.add(Roles.ROLE_ADMIN.name());
        return rolesSet;
    }

    private Set<String> rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users() {
        var rolesSet = new HashSet<String>();
        rolesSet.add(Roles.ROLE_SUPER_ADMIN.name());
        return rolesSet;
    }

    private Set<String> rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users() {
        var rolesSet = rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users();
        rolesSet.add(Roles.ROLE_ADMIN.name());
        return rolesSet;
    }

    private Set<String> usersWithTheseRoles_AreAllowedTo_Read_Users() {
        var rolesSet = new HashSet<String>();
        rolesSet.add(Roles.ROLE_SUPER_ADMIN.name());
        rolesSet.add(Roles.ROLE_ADMIN.name());
        rolesSet.add(Roles.ROLE_MANAGE_USERS.name());
        return rolesSet;
    }

    @Test
    public void test_CreateUser_UsingUserWithRoleSuperAdmin() {
        var creator = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersToBeCreatedBySuperAdmin = new HashSet<UserDto>();
        usersToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        TEST_USERS.addAll(usersToBeCreatedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var user : usersToBeCreatedBySuperAdmin) {
            LOGGER.info("Attempting to create user:\n{}\nusing super admin user '{}'", ToJsonForLoggingUtil.toJson(user), creator.getUsername());
            var response = AdminUserCallsHelper.createUser(accessToken, user);
            LOGGER.info("Validating response for attempt to create user:\n{}", response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfUserCreation(response, creator, user);
        }
    }

    @Test
    public void test_CreateUser_UsingUserWithRoleAdmin() {
        var creator = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersToBeCreatedByAdmin = new HashSet<UserDto>();
        usersToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto());
        usersToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        TEST_USERS.addAll(usersToBeCreatedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var user : usersToBeCreatedByAdmin) {
            LOGGER.info("Attempting to create user:\n{}\nusing admin user '{}'", ToJsonForLoggingUtil.toJson(user), creator.getUsername());
            var response = AdminUserCallsHelper.createUser(accessToken, user);
            LOGGER.info("Validating response for attempt to create user:\n{}", response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfUserCreation(response, creator, user);
        }
    }

    @Test
    public void test_CreateUser_UsingUserWithRoleManageUsers() {
        var creator = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersToBeCreatedByManageUsers = new HashSet<UserDto>();
        usersToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        TEST_USERS.addAll(usersToBeCreatedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var user : usersToBeCreatedByManageUsers) {
            LOGGER.info("Attempting to create user:\n{}\nusing manage users user '{}'", ToJsonForLoggingUtil.toJson(user), creator.getUsername());
            var response = AdminUserCallsHelper.createUser(accessToken, user);
            LOGGER.info("Validating response for attempt to create user:\n{}", response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfUserCreation(response, creator, user);
        }
    }

    @Test
    public void test_CreateUser_UsingUsersWhoAreNotAllowedToCreateUser() {
        var creators = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            creators.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(creators);
        var testUser = DtosHelper.createRandomUserDto();
        for (var creator : creators) {
            var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
            LOGGER.info("Attempting to create user\n{}\nusing user '{}'", ToJsonForLoggingUtil.toJson(testUser), creator.getUsername());
            var response = AdminUserCallsHelper.createUser(accessToken, testUser);
            LOGGER.info("Validating response for attempt to create user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_CreateUser_UsingUserWithRoleSuperAdmin_NotAllowedToCreate() {
        var creator = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersNotToBeCreatedBySuperAdmin = new HashSet<UserDto>();
        usersNotToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var user : usersNotToBeCreatedBySuperAdmin) {
            LOGGER.info("Attempting to create user:\n{}\nusing super admin user '{}'", ToJsonForLoggingUtil.toJson(user), creator.getUsername());
            var response = AdminUserCallsHelper.createUser(accessToken, user);
            LOGGER.info("Validating response for attempt to create user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_CreateUser_UsingUserWithRoleAdmin_NotAllowedToCreate() {
        var creator = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersNotToBeCreatedByAdmin = new HashSet<UserDto>();
        usersNotToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var user : usersNotToBeCreatedByAdmin) {
            LOGGER.info("Attempting to create user:\n{}\nusing admin user '{}'", ToJsonForLoggingUtil.toJson(user), creator.getUsername());
            var response = AdminUserCallsHelper.createUser(accessToken, user);
            LOGGER.info("Validating response for attempt to create user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_CreateUser_UsingUserWithRoleManageUsers_NotAllowedToCreate() {
        var creator = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersNotToBeCreatedByManageUsers = new HashSet<UserDto>();
        usersNotToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var user : usersNotToBeCreatedByManageUsers) {
            LOGGER.info("Attempting to create user:\n{}\nusing manage users user '{}'", ToJsonForLoggingUtil.toJson(user), creator.getUsername());
            var response = AdminUserCallsHelper.createUser(accessToken, user);
            LOGGER.info("Validating response for attempt to create user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_CreateUser_InvalidInputs() {
        var creator = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        var testUser = new UserDto();
        LOGGER.info("Attempting to create user with null username:\n{}", ToJsonForLoggingUtil.toJson(testUser));
        var response = AdminUserCallsHelper.createUser(accessToken, testUser);
        LOGGER.info("Validating response for attempt to create user with null username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            testUser.setUsername(entry);
            LOGGER.info("Attempting to create user with invalid username: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testUser));
            response = AdminUserCallsHelper.createUser(accessToken, testUser);
            LOGGER.info("Validating response for attempt to create user with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        testUser.setUsername("AutoTestUser_" + uniqueString);
        LOGGER.info("Attempting to create user with null password:\n{}", ToJsonForLoggingUtil.toJson(testUser));
        response = AdminUserCallsHelper.createUser(accessToken, testUser);
        LOGGER.info("Validating response for attempt to create user with null password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            testUser.setPassword(entry);
            LOGGER.info("Attempting to create user with invalid password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testUser));
            response = AdminUserCallsHelper.createUser(accessToken, testUser);
            LOGGER.info("Validating response for attempt to create user with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setPassword("Password@1" + uniqueString);
        LOGGER.info("Attempting to create user with null email:\n{}", ToJsonForLoggingUtil.toJson(testUser));
        response = AdminUserCallsHelper.createUser(accessToken, testUser);
        LOGGER.info("Validating response for attempt to create user with null email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            testUser.setEmail(entry);
            LOGGER.info("Attempting to create user with invalid email: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testUser));
            response = AdminUserCallsHelper.createUser(accessToken, testUser);
            LOGGER.info("Validating response for attempt to create user with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setEmail("user_" + uniqueString + "@example.com");
        LOGGER.info("Attempting to create user with null first name:\n{}", ToJsonForLoggingUtil.toJson(testUser));
        response = AdminUserCallsHelper.createUser(accessToken, testUser);
        LOGGER.info("Validating response for attempt to create user with null first name:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setFirstName(entry);
            LOGGER.info("Attempting to create user with invalid first name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testUser));
            response = AdminUserCallsHelper.createUser(accessToken, testUser);
            LOGGER.info("Validating response for attempt to create user with invalid first name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setFirstName("F");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setMiddleName(entry);
            LOGGER.info("Attempting to create user with invalid middle name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testUser));
            response = AdminUserCallsHelper.createUser(accessToken, testUser);
            LOGGER.info("Validating response for attempt to create user with invalid middle name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setMiddleName("M");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setLastName(entry);
            LOGGER.info("Attempting to create user with invalid last name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testUser));
            response = AdminUserCallsHelper.createUser(accessToken, testUser);
            LOGGER.info("Validating response for attempt to create user with invalid last name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setLastName("L");
        testUser.setUsername(creator.getUsername());
        LOGGER.info("Attempting to create user with existing username '{}':\n{}", creator.getUsername(), ToJsonForLoggingUtil.toJson(testUser));
        response = AdminUserCallsHelper.createUser(accessToken, testUser);
        LOGGER.info("Validating response for attempt to create user with existing username '{}':\n{}", creator.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        testUser.setUsername("AutoTestUser_" + uniqueString);
        testUser.setEmail(creator.getEmail());
        LOGGER.info("Attempting to create user with existing email '{}':\n{}", creator.getEmail(), ToJsonForLoggingUtil.toJson(testUser));
        response = AdminUserCallsHelper.createUser(accessToken, testUser);
        LOGGER.info("Validating response for attempt to create user with existing email '{}':\n{}", creator.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        testUser.setEmail("user_" + uniqueString + "@example.com");
        testUser.setRoles(Set.of("ROLE_INVALID_" + uniqueString));
        LOGGER.info("Attempting to create user with invalid roles: '{}'\n{}", testUser.getRoles(), ToJsonForLoggingUtil.toJson(testUser));
        response = AdminUserCallsHelper.createUser(accessToken, testUser);
        LOGGER.info("Validating response for attempt to create user with invalid roles: '{}'\n{}", testUser.getRoles(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("non_existing_roles", not(empty()));
    }

    @Test
    public void test_CreateUsers_UsingUserWithRoleSuperAdmin() {
        var creator = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersToBeCreatedBySuperAdmin = new HashSet<UserDto>();
        usersToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersToBeCreatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        TEST_USERS.addAll(usersToBeCreatedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        LOGGER.info("Attempting to create users using super admin user '{}':\n{}", creator.getUsername(), ToJsonForLoggingUtil.toJson(usersToBeCreatedBySuperAdmin));
        var response = AdminUserCallsHelper.createUsers(accessToken, usersToBeCreatedBySuperAdmin);
        LOGGER.info("Validating response for attempt to create users:\n{}", response.getBody().asPrettyString());
        ResponseValidatorHelper.validateResponseOfUsersCreation(response, creator, usersToBeCreatedBySuperAdmin, "");
    }

    @Test
    public void test_CreateUsers_UsingUserWithRoleAdmin() {
        var creator = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersToBeCreatedByAdmin = new HashSet<UserDto>();
        usersToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto());
        usersToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersToBeCreatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        TEST_USERS.addAll(usersToBeCreatedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        LOGGER.info("Attempting to create users using admin user '{}':\n{}", creator.getUsername(), ToJsonForLoggingUtil.toJson(usersToBeCreatedByAdmin));
        var response = AdminUserCallsHelper.createUsers(accessToken, usersToBeCreatedByAdmin);
        LOGGER.info("Validating response for attempt to create users:\n{}", response.getBody().asPrettyString());
        ResponseValidatorHelper.validateResponseOfUsersCreation(response, creator, usersToBeCreatedByAdmin, "");
    }

    @Test
    public void test_CreateUsers_UsingUserWithRoleManageUsers() {
        var creator = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersToBeCreatedByManageUsers = new HashSet<UserDto>();
        usersToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersToBeCreatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        TEST_USERS.addAll(usersToBeCreatedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        LOGGER.info("Attempting to create users using manage users user '{}':\n{}", creator.getUsername(), ToJsonForLoggingUtil.toJson(usersToBeCreatedByManageUsers));
        var response = AdminUserCallsHelper.createUsers(accessToken, usersToBeCreatedByManageUsers);
        LOGGER.info("Validating response for attempt to create users:\n{}", response.getBody().asPrettyString());
        ResponseValidatorHelper.validateResponseOfUsersCreation(response, creator, usersToBeCreatedByManageUsers, "");
    }

    @Test
    public void test_CreateUsers_UsingUsersWhoAreNotAllowedToCreateUsers() {
        var creators = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            creators.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(creators);
        var testUsers = DtosHelper.createRandomUserDtos(2);
        for (var creator : creators) {
            var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
            LOGGER.info("Attempting to create users:\n{}\nusing user '{}'", ToJsonForLoggingUtil.toJson(testUsers), creator.getUsername());
            var response = AdminUserCallsHelper.createUsers(accessToken, testUsers);
            LOGGER.info("Validating response for attempt to create users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_CreateUsers_UsingUserWithRoleSuperAdmin_NotAllowedToCreate() {
        var creator = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersNotToBeCreatedBySuperAdmin = new HashSet<Set<UserDto>>();
        usersNotToBeCreatedBySuperAdmin.add(Set.of(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users())));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeCreatedBySuperAdmin.add(Set.of(DtosHelper.createRandomUserDto(Set.of(role))));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeCreatedBySuperAdmin.add(Set.of(DtosHelper.createRandomUserDto(roles)));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var users : usersNotToBeCreatedBySuperAdmin) {
            LOGGER.info("Attempting to create users:\n{}\nusing super admin user '{}'", ToJsonForLoggingUtil.toJson(users), creator.getUsername());
            var response = AdminUserCallsHelper.createUsers(accessToken, users);
            LOGGER.info("Validating response for attempt to create users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_CreateUsers_UsingUserWithRoleAdmin_NotAllowedToCreate() {
        var creator = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersNotToBeCreatedByAdmin = new HashSet<Set<UserDto>>();
        usersNotToBeCreatedByAdmin.add(Set.of(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users())));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeCreatedByAdmin.add(Set.of(DtosHelper.createRandomUserDto(Set.of(role))));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeCreatedByAdmin.add(Set.of(DtosHelper.createRandomUserDto(roles)));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var users : usersNotToBeCreatedByAdmin) {
            LOGGER.info("Attempting to create users:\n{}\nusing admin user '{}'", ToJsonForLoggingUtil.toJson(users), creator.getUsername());
            var response = AdminUserCallsHelper.createUsers(accessToken, users);
            LOGGER.info("Validating response for attempt to create users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_CreateUsers_UsingUserWithRoleManageUsers_NotAllowedToCreate() {
        var creator = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersNotToBeCreatedByManageUsers = new HashSet<Set<UserDto>>();
        usersNotToBeCreatedByManageUsers.add(Set.of(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users())));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeCreatedByManageUsers.add(Set.of(DtosHelper.createRandomUserDto(Set.of(role))));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeCreatedByManageUsers.add(Set.of(DtosHelper.createRandomUserDto(roles)));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        for (var users : usersNotToBeCreatedByManageUsers) {
            LOGGER.info("Attempting to create users:\n{}\nusing manage users user '{}'", ToJsonForLoggingUtil.toJson(users), creator.getUsername());
            var response = AdminUserCallsHelper.createUsers(accessToken, users);
            LOGGER.info("Validating response for attempt to create users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_CreateUsers_InvalidInputs() {
        var creator = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        var testUser = new UserDto();
        LOGGER.info("Attempting to create users with null username:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testUser)));
        var response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to create users with null username:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            testUser.setUsername(entry);
            LOGGER.info("Attempting to create users with invalid username: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testUser)));
            response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to create users with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        testUser.setUsername("AutoTestUser_" + uniqueString);
        LOGGER.info("Attempting to create users with null password:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testUser)));
        response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to create users with null password:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            testUser.setPassword(entry);
            LOGGER.info("Attempting to create users with invalid password: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testUser)));
            response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to create users with invalid password: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setPassword("Password@1" + uniqueString);
        LOGGER.info("Attempting to create users with null email:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testUser)));
        response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to create users with null email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            testUser.setEmail(entry);
            LOGGER.info("Attempting to create users with invalid email: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testUser)));
            response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to create users with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setEmail("user_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Attempting to create users with null first name:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testUser)));
        response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to create users with null first name:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setFirstName(entry);
            LOGGER.info("Attempting to create users with invalid first name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testUser)));
            response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to create users with invalid first name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setFirstName("F");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setMiddleName(entry);
            LOGGER.info("Attempting to create users with invalid middle name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testUser)));
            response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to create users with invalid middle name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setMiddleName("M");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setLastName(entry);
            LOGGER.info("Attempting to create users with invalid last name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testUser)));
            response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to create users with invalid last name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setLastName("L");
        var testUser2 = DtosHelper.createRandomUserDto();
        testUser.setUsername(testUser2.getUsername());
        testUser.setEmail(testUser2.getEmail());
        LOGGER.info("Attempting to create users with duplicate username and email:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testUser, testUser2)));
        response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser, testUser2));
        LOGGER.info("Validating response for attempt to create users with duplicate username and email:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400)
                .body("duplicate_usernames_in_request", not(empty()))
                .body("duplicate_emails_in_request", not(empty()));
        testUser.setUsername(creator.getUsername());
        LOGGER.info("Attempting to create users with existing username '{}':\n{}", creator.getUsername(), ToJsonForLoggingUtil.toJson(Set.of(testUser)));
        response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to create users with existing username '{}':\n{}", creator.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("already_taken_usernames", not(empty()));
        testUser.setUsername("AutoTestUser_" + uniqueString);
        testUser.setEmail(creator.getEmail());
        LOGGER.info("Attempting to create users with existing email '{}':\n{}", creator.getEmail(), ToJsonForLoggingUtil.toJson(Set.of(testUser)));
        response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to create users with existing email '{}':\n{}", creator.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("already_taken_emails", not(empty()));
        testUser.setEmail("user_" + uniqueString.toLowerCase() + "@example.com");
        testUser.setRoles(Set.of("ROLE_INVALID_" + uniqueString));
        LOGGER.info("Attempting to create users with invalid roles: '{}'\n{}", testUser.getRoles(), ToJsonForLoggingUtil.toJson(Set.of(testUser)));
        response = AdminUserCallsHelper.createUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to create users with invalid roles: '{}'\n{}", testUser.getRoles(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("non_existing_roles", not(empty()));
    }

    @Test
    public void test_DeleteUserByUsername_UsingUserWithRoleSuperAdmin() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCanBeDeletedBySuperAdmin = new HashSet<UserDto>();
        usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersThatCanBeDeletedBySuperAdmin) {
            LOGGER.info("Using super admin user '{}' to delete user '{}'", deleter.getUsername(), user.getUsername());
            var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, user.getUsername());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
        }
    }

    @Test
    public void test_DeleteUserByUsername_UsingUserWithRoleAdmin() {
        var deleter = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCanBeDeletedByAdmin = new HashSet<UserDto>();
        usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersThatCanBeDeletedByAdmin) {
            LOGGER.info("Using admin user '{}' to delete user '{}'", deleter.getUsername(), user.getUsername());
            var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, user.getUsername());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
        }
    }

    @Test
    public void test_DeleteUserByUsername_UsingUserWithRoleManageUsers() {
        var deleter = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCanBeDeletedByManageUsers = new HashSet<UserDto>();
        usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersThatCanBeDeletedByManageUsers) {
            LOGGER.info("Using manage users user '{}' to delete user '{}'", deleter.getUsername(), user.getUsername());
            var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, user.getUsername());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
        }
    }

    @Test
    public void test_DeleteUserByUsername_UsingUsersWhoAreNotAllowedToDelete() {
        var deleters = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            deleters.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(deleters);
        var testUser = DtosHelper.createRandomUserDto();
        for (var deleter : deleters) {
            var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
            LOGGER.info("Attempting to delete user '{}' using user '{}'", testUser.getUsername(), deleter.getUsername());
            var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, testUser.getUsername());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", testUser.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_DeleteUserByUsername_InvalidInputs() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to delete user with invalid username: '{}'", entry);
            var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, entry);
            LOGGER.info("Validating response for attempt to delete user with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found with username: '" + entry + "'"));
        }
        LOGGER.info("Attempting to delete your own account '{}'", deleter.getUsername());
        var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, deleter.getUsername());
        LOGGER.info("Validating response for attempt to delete your own account '{}':\n{}", deleter.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("You cannot delete your own account using this endpoint"));
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to delete user with non-existing username '{}'", "non_existing_user_" + uniqueString);
        response = AdminUserCallsHelper.deleteUserByUsername(accessToken, "non_existing_user_" + uniqueString);
        LOGGER.info("Validating response for attempt to delete user with non-existing username '{}':\n{}", "non_existing_user_" + uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with username: '" + "non_existing_user_" + uniqueString + "'"));
    }

    @Test
    public void test_DeleteUserByUsername_UsingUserWithRoleSuperAdmin_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersNotToBeDeletedBySuperAdmin = new HashSet<UserDto>();
        usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersNotToBeDeletedBySuperAdmin) {
            LOGGER.info("Attempting to delete user '{}' using super admin user '{}'", user.getUsername(), deleter.getUsername());
            var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, user.getUsername());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DeleteUserByUsername_UsingUserWithRoleAdmin_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersNotToBeDeletedByAdmin = new HashSet<UserDto>();
        usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersNotToBeDeletedByAdmin) {
            LOGGER.info("Attempting to delete user '{}' using admin user '{}'", user.getUsername(), deleter.getUsername());
            var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, user.getUsername());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DeleteUserByUsername_UsingUserWithRoleManageUsers_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersNotToBeDeletedByManageUsers = new HashSet<UserDto>();
        usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersNotToBeDeletedByManageUsers) {
            LOGGER.info("Attempting to delete user '{}' using manage users user '{}'", user.getUsername(), deleter.getUsername());
            var response = AdminUserCallsHelper.deleteUserByUsername(accessToken, user.getUsername());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", user.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DeleteUserByEmail_UsingUserWithRoleSuperAdmin() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCanBeDeletedBySuperAdmin = new HashSet<UserDto>();
        usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersThatCanBeDeletedBySuperAdmin) {
            LOGGER.info("Using super admin user '{}' to delete user '{}'", deleter.getEmail(), user.getEmail());
            var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, user.getEmail());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
        }
    }

    @Test
    public void test_DeleteUserByEmail_UsingUserWithRoleAdmin() {
        var deleter = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCanBeDeletedByAdmin = new HashSet<UserDto>();
        usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersThatCanBeDeletedByAdmin) {
            LOGGER.info("Using admin user '{}' to delete user '{}'", deleter.getEmail(), user.getEmail());
            var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, user.getEmail());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
        }
    }

    @Test
    public void test_DeleteUserByEmail_UsingUserWithRoleManageUsers() {
        var deleter = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCanBeDeletedByManageUsers = new HashSet<UserDto>();
        usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersThatCanBeDeletedByManageUsers) {
            LOGGER.info("Using manage users user '{}' to delete user '{}'", deleter.getEmail(), user.getEmail());
            var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, user.getEmail());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
        }
    }

    @Test
    public void test_DeleteUserByEmail_UsingUsersWhoAreNotAllowedToDelete() {
        var deleters = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            deleters.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(deleters);
        var testUser = DtosHelper.createRandomUserDto();
        for (var deleter : deleters) {
            var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
            LOGGER.info("Attempting to delete user '{}' using user '{}'", testUser.getEmail(), deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, testUser.getEmail());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", testUser.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_DeleteUserByEmail_InvalidInputs() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to delete user with invalid email: '{}'", entry);
            var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, entry);
            LOGGER.info("Validating response for attempt to delete user with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found with email: '" + entry + "'"));
        }
        LOGGER.info("Attempting to delete your own account '{}'", deleter.getEmail());
        var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, deleter.getEmail());
        LOGGER.info("Validating response for attempt to delete your own account '{}':\n{}", deleter.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("You cannot delete your own account using this endpoint"));
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to delete user with non-existing email '{}'", "non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        response = AdminUserCallsHelper.deleteUserByEmail(accessToken, "non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Validating response for attempt to delete user with non-existing email '{}':\n{}", "non_existing_user_" + uniqueString.toLowerCase() + "@example.com", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with email: '" + "non_existing_user_" + uniqueString.toLowerCase() + "@example.com'"));
    }

    @Test
    public void test_DeleteUserByEmail_UsingUserWithRoleSuperAdmin_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersNotToBeDeletedBySuperAdmin = new HashSet<UserDto>();
        usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersNotToBeDeletedBySuperAdmin) {
            LOGGER.info("Attempting to delete user '{}' using super admin user '{}'", user.getEmail(), deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, user.getEmail());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DeleteUserByEmail_UsingUserWithRoleAdmin_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersNotToBeDeletedByAdmin = new HashSet<UserDto>();
        usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersNotToBeDeletedByAdmin) {
            LOGGER.info("Attempting to delete user '{}' using admin user '{}'", user.getEmail(), deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, user.getEmail());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DeleteUserByEmail_UsingUserWithRoleManageUsers_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersNotToBeDeletedByManageUsers = new HashSet<UserDto>();
        usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var user : usersNotToBeDeletedByManageUsers) {
            LOGGER.info("Attempting to delete user '{}' using manage users user '{}'", user.getEmail(), deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUserByEmail(accessToken, user.getEmail());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DeleteUser_UsingUserWithRoleSuperAdmin() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCanBeDeletedBySuperAdmin = new HashSet<UserDto>();
        usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = 0;
        for (var user : usersThatCanBeDeletedBySuperAdmin) {
            LOGGER.info("Using super admin user '{}' to delete user '{}'", i % 2 == 0 ? deleter.getUsername() : deleter.getEmail(), i % 2 == 0 ? user.getUsername() : user.getEmail());
            var response = AdminUserCallsHelper.deleteUser(accessToken, i % 2 == 0 ? user.getUsername() : user.getEmail());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", i % 2 == 0 ? user.getUsername() : user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
            i++;
        }
    }

    @Test
    public void test_DeleteUser_UsingUserWithRoleAdmin() {
        var deleter = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCanBeDeletedByAdmin = new HashSet<UserDto>();
        usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = 0;
        for (var user : usersThatCanBeDeletedByAdmin) {
            LOGGER.info("Using admin user '{}' to delete user '{}'", i % 2 == 0 ? deleter.getUsername() : deleter.getEmail(), i % 2 == 0 ? user.getUsername() : user.getEmail());
            var response = AdminUserCallsHelper.deleteUser(accessToken, i % 2 == 0 ? user.getUsername() : user.getEmail());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", i % 2 == 0 ? user.getUsername() : user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
            i++;
        }
    }

    @Test
    public void test_DeleteUser_UsingUserWithRoleManageUsers() {
        var deleter = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCanBeDeletedByManageUsers = new HashSet<UserDto>();
        usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = 0;
        for (var user : usersThatCanBeDeletedByManageUsers) {
            LOGGER.info("Using manage users user '{}' to delete user '{}'", i % 2 == 0 ? deleter.getUsername() : deleter.getEmail(), i % 2 == 0 ? user.getUsername() : user.getEmail());
            var response = AdminUserCallsHelper.deleteUser(accessToken, i % 2 == 0 ? user.getUsername() : user.getEmail());
            LOGGER.info("Validating response for deletion of user '{}':\n{}", i % 2 == 0 ? user.getUsername() : user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", containsString("User deleted successfully"));
            i++;
        }
    }

    @Test
    public void test_DeleteUser_UsingUsersWhoAreNotAllowedToDelete() {
        var deleters = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            deleters.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(deleters);
        var testUser = DtosHelper.createRandomUserDto();
        var i = 0;
        for (var deleter : deleters) {
            var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
            LOGGER.info("Attempting to delete user '{}' using user '{}'", i % 2 == 0 ? testUser.getUsername() : testUser.getEmail(), i % 2 == 0 ? deleter.getUsername() : deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUser(accessToken, testUser.getUsername());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", i % 2 == 0 ? testUser.getUsername() : testUser.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
            i++;
        }
    }

    @Test
    public void test_DeleteUser_InvalidInputs() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to delete user with invalid input: '{}'", entry);
            var response = AdminUserCallsHelper.deleteUser(accessToken, entry);
            LOGGER.info("Validating response for attempt to delete user with invalid input: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to delete user with invalid email: '{}'", entry);
            var response = AdminUserCallsHelper.deleteUser(accessToken, entry);
            LOGGER.info("Validating response for attempt to delete user with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        LOGGER.info("Attempting to delete your own account using username '{}'", deleter.getUsername());
        var response = AdminUserCallsHelper.deleteUser(accessToken, deleter.getUsername());
        LOGGER.info("Validating response for attempt to delete your own account using username '{}':\n{}", deleter.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("You cannot delete your own account using this endpoint"));
        LOGGER.info("Attempting to delete your own account using email '{}'", deleter.getEmail());
        response = AdminUserCallsHelper.deleteUser(accessToken, deleter.getEmail());
        LOGGER.info("Validating response for attempt to delete your own account using email '{}':\n{}", deleter.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("You cannot delete your own account using this endpoint"));
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to delete user with non-existing username '{}'", "non_existing_user_" + uniqueString);
        response = AdminUserCallsHelper.deleteUser(accessToken, "non_existing_user_" + uniqueString);
        LOGGER.info("Validating response for attempt to delete user with non-existing username '{}':\n{}", "non_existing_user_" + uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with username: '" + "non_existing_user_" + uniqueString + "'"));
        LOGGER.info("Attempting to delete user with non-existing email '{}'", "non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        response = AdminUserCallsHelper.deleteUser(accessToken, "non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Validating response for attempt to delete user with non-existing email '{}':\n{}", "non_existing_user_" + uniqueString.toLowerCase() + "@example.com", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with email: '" + "non_existing_user_" + uniqueString.toLowerCase() + "@example.com'"));
    }

    @Test
    public void test_DeleteUser_UsingUserWithRoleSuperAdmin_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersNotToBeDeletedBySuperAdmin = new HashSet<UserDto>();
        usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = 0;
        for (var user : usersNotToBeDeletedBySuperAdmin) {
            LOGGER.info("Attempting to delete user '{}' using super admin user '{}'", i % 2 == 0 ? user.getUsername() : user.getEmail(), i % 2 == 0 ? deleter.getUsername() : deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUser(accessToken, i % 2 == 0 ? user.getUsername() : user.getEmail());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", i % 2 == 0 ? user.getUsername() : user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
            i++;
        }
    }

    @Test
    public void test_DeleteUser_UsingUserWithRoleAdmin_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersNotToBeDeletedByAdmin = new HashSet<UserDto>();
        usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = 0;
        for (var user : usersNotToBeDeletedByAdmin) {
            LOGGER.info("Attempting to delete user '{}' using admin user '{}'", i % 2 == 0 ? user.getUsername() : user.getEmail(), i % 2 == 0 ? deleter.getUsername() : deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUser(accessToken, i % 2 == 0 ? user.getUsername() : user.getEmail());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", i % 2 == 0 ? user.getUsername() : user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
            i++;
        }
    }

    @Test
    public void test_DeleteUser_UsingUserWithRoleManageUsers_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersNotToBeDeletedByManageUsers = new HashSet<UserDto>();
        usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersNotToBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersNotToBeDeletedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = 0;
        for (var user : usersNotToBeDeletedByManageUsers) {
            LOGGER.info("Attempting to delete user '{}' using manage users user '{}'", i % 2 == 0 ? user.getUsername() : user.getEmail(), i % 2 == 0 ? deleter.getUsername() : deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUser(accessToken, i % 2 == 0 ? user.getUsername() : user.getEmail());
            LOGGER.info("Validating response for attempt to delete user '{}':\n{}", i % 2 == 0 ? user.getUsername() : user.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_user_with_these_roles", not(empty()));
            i++;
        }
    }

    @Test
    public void test_DeleteUsers_UsingUserWithRoleSuperAdmin() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCanBeDeletedBySuperAdmin = new HashSet<UserDto>();
        usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = new AtomicInteger();
        var identifiers = usersThatCanBeDeletedBySuperAdmin.stream().map(user -> i.getAndIncrement() % 2 == 0 ? user.getUsername() : user.getEmail()).collect(Collectors.toSet());
        LOGGER.info("Using super admin user '{}' to delete users:\n{}", deleter.getUsername(), ToJsonForLoggingUtil.toJson(identifiers));
        var response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for deletion of users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Users deleted successfully"));
    }

    @Test
    public void test_DeleteUsers_UsingUserWithRoleAdmin() {
        var deleter = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCanBeDeletedByAdmin = new HashSet<UserDto>();
        usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = new AtomicInteger();
        var identifiers = usersThatCanBeDeletedByAdmin.stream().map(user -> i.getAndIncrement() % 2 == 0 ? user.getUsername() : user.getEmail()).collect(Collectors.toSet());
        LOGGER.info("Using admin user '{}' to delete users:\n{}", deleter.getUsername(), ToJsonForLoggingUtil.toJson(identifiers));
        var response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for deletion of users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Users deleted successfully"));
    }

    @Test
    public void test_DeleteUsers_UsingUserWithRoleManageUsers() {
        var deleter = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCanBeDeletedByManageUsers = new HashSet<UserDto>();
        usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeDeletedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = new AtomicInteger();
        var identifiers = usersThatCanBeDeletedByManageUsers.stream().map(user -> i.getAndIncrement() % 2 == 0 ? user.getUsername() : user.getEmail()).collect(Collectors.toSet());
        LOGGER.info("Using manage users user '{}' to delete users:\n{}", deleter.getUsername(), ToJsonForLoggingUtil.toJson(identifiers));
        var response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for deletion of users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(200).body("message", containsString("Users deleted successfully"));
    }

    @Test
    public void test_DeleteUsers_UsingUsersWhoAreNotAllowedToDelete() {
        var deleters = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            deleters.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(deleters);
        var testUser = DtosHelper.createRandomUserDto();
        for (var deleter : deleters) {
            var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
            LOGGER.info("Attempting to delete users:\n{}\nusing user '{}'", ToJsonForLoggingUtil.toJson(Set.of(testUser.getUsername(), testUser.getEmail())), deleter.getUsername());
            var response = AdminUserCallsHelper.deleteUsers(accessToken, Set.of(testUser.getUsername(), testUser.getEmail()));
            LOGGER.info("Validating response for attempt to delete users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_DeleteUsers_InvalidInputs() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var invalidInputs = new HashSet<>(InvalidInputsHelper.invalidUsernames());
        invalidInputs.addAll(InvalidInputsHelper.invalidEmails());
        invalidInputs.add(deleter.getUsername());
        invalidInputs.add(deleter.getEmail());
        LOGGER.info("Attempting to delete users with invalid inputs: {}", ToJsonForLoggingUtil.toJson(invalidInputs));
        var response = AdminUserCallsHelper.deleteUsers(accessToken, invalidInputs);
        LOGGER.info("Validating response for attempt to delete users with invalid inputs:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400)
                .body("users_found_with_these_usernames_or_emails", not(empty()))
                .body("you_cannot_delete_your_own_account_using_this_endpoint", not(empty()));
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        invalidInputs.clear();
        invalidInputs.add("non_existing_user_" + uniqueString);
        invalidInputs.add("non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Attempting to delete users with non-existing usernames and emails: {}", ToJsonForLoggingUtil.toJson(invalidInputs));
        response = AdminUserCallsHelper.deleteUsers(accessToken, invalidInputs);
        LOGGER.info("Validating response for attempt to delete users with non-existing usernames and emails:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400)
                .body("not_found_usernames", not(empty()))
                .body("not_found_emails", not(empty()));
    }

    @Test
    public void test_DeleteUsers_UsingUserWithRoleSuperAdmin_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCannotBeDeletedBySuperAdmin = new HashSet<UserDto>();
        usersThatCannotBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeDeletedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeDeletedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = new AtomicInteger();
        var identifiers = usersThatCannotBeDeletedBySuperAdmin.stream().map(user -> i.getAndIncrement() % 2 == 0 ? user.getUsername() : user.getEmail()).collect(Collectors.toSet());
        var j = 0;
        for (var user : identifiers) {
            LOGGER.info("Attempting to delete users:\n{}\nusing super admin user '{}'", ToJsonForLoggingUtil.toJson(Set.of(user)), j % 2 == 0 ? deleter.getUsername() : deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUsers(accessToken, Set.of(user));
            LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", Set.of(user), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
            j++;
        }
        LOGGER.info("Attempting to delete users:\n{}\nusing super admin user '{}'", ToJsonForLoggingUtil.toJson(identifiers), deleter.getUsername());
        var response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", identifiers, response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
        var userThatCanBeDeletedBySuperAdmin = createTestUser();
        identifiers.add(userThatCanBeDeletedBySuperAdmin.getUsername());
        identifiers.add(userThatCanBeDeletedBySuperAdmin.getEmail());
        LOGGER.info("Attempting to delete users:\n{}\nusing super admin user '{}'", ToJsonForLoggingUtil.toJson(identifiers), deleter.getUsername());
        response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", identifiers, response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
    }

    @Test
    public void test_DeleteUsers_UsingUserWithRoleAdmin_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCannotBeDeletedByAdmin = new HashSet<UserDto>();
        usersThatCannotBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeDeletedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeDeletedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = new AtomicInteger();
        var identifiers = usersThatCannotBeDeletedByAdmin.stream().map(user -> i.getAndIncrement() % 2 == 0 ? user.getUsername() : user.getEmail()).collect(Collectors.toSet());
        var j = 0;
        for (var user : identifiers) {
            LOGGER.info("Attempting to delete users:\n{}\nusing admin user '{}'", ToJsonForLoggingUtil.toJson(Set.of(user)), j % 2 == 0 ? deleter.getUsername() : deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUsers(accessToken, Set.of(user));
            LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", Set.of(user), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
            j++;
        }
        LOGGER.info("Attempting to delete users:\n{}\nusing admin user '{}'", ToJsonForLoggingUtil.toJson(identifiers), deleter.getUsername());
        var response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", identifiers, response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
        var userThatCanBeDeletedByAdmin = createTestUser();
        identifiers.add(userThatCanBeDeletedByAdmin.getUsername());
        identifiers.add(userThatCanBeDeletedByAdmin.getEmail());
        LOGGER.info("Attempting to delete users:\n{}\nusing admin user '{}'", ToJsonForLoggingUtil.toJson(identifiers), deleter.getUsername());
        response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", identifiers, response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
    }

    @Test
    public void test_DeleteUsers_UsingUserWithRoleManageUsers_NotAllowedToDelete() {
        var deleter = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCannotBeDeletedByManageUsers = new HashSet<UserDto>();
        usersThatCannotBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeDeletedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeDeletedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var i = new AtomicInteger();
        var identifiers = usersThatCannotBeDeletedByManageUsers.stream().map(user -> i.getAndIncrement() % 2 == 0 ? user.getUsername() : user.getEmail()).collect(Collectors.toSet());
        var j = 0;
        for (var user : identifiers) {
            LOGGER.info("Attempting to delete users:\n{}\nusing manage users user '{}'", ToJsonForLoggingUtil.toJson(Set.of(user)), j % 2 == 0 ? deleter.getUsername() : deleter.getEmail());
            var response = AdminUserCallsHelper.deleteUsers(accessToken, Set.of(user));
            LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", Set.of(user), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
            j++;
        }
        LOGGER.info("Attempting to delete users:\n{}\nusing manage users user '{}'", ToJsonForLoggingUtil.toJson(identifiers), deleter.getUsername());
        var response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", identifiers, response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
        var userThatCanBeDeletedByManageUsers = createTestUser();
        identifiers.add(userThatCanBeDeletedByManageUsers.getUsername());
        identifiers.add(userThatCanBeDeletedByManageUsers.getEmail());
        LOGGER.info("Attempting to delete users:\n{}\nusing manage users user '{}'", ToJsonForLoggingUtil.toJson(identifiers), deleter.getUsername());
        response = AdminUserCallsHelper.deleteUsers(accessToken, identifiers);
        LOGGER.info("Validating response for attempt to delete users:\n{}\n{}", identifiers, response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_delete_users_with_these_roles", not(empty()));
    }

    @Test
    public void test_GetUserByUsername_UsingUsersWhoAreAllowedToRead() {
        var readers = new HashSet<UserDto>();
        readers.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AreAllowedTo_Read_Users()));
        for (var role : usersWithTheseRoles_AreAllowedTo_Read_Users()) {
            readers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users();
        roles.addAll(usersWithTheseRoles_AreAllowedTo_Read_Users());
        readers.add(DtosHelper.createRandomUserDto(roles));
        var testUser = DtosHelper.createRandomUserDto();
        readers.add(testUser);
        createTestUsers(readers);
        readers.remove(testUser);
        for (var reader : readers) {
            var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
            LOGGER.info("Attempting to get user by username '{}' using user '{}'", testUser.getUsername(), reader.getUsername());
            var response = AdminUserCallsHelper.getUserByUsername(accessToken, testUser.getUsername());
            LOGGER.info("Validating response for attempt to get user by username '{}':\n{}", testUser.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("username", equalTo(testUser.getUsername()));
        }
    }

    @Test
    public void test_GetUserByUsername_UsingUsersWhoAreNotAllowedToRead() {
        var readers = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            readers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(readers);
        var testUser = DtosHelper.createRandomUserDto();
        for (var reader : readers) {
            var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
            LOGGER.info("Attempting to get user by username '{}' using user '{}'", testUser.getUsername(), reader.getUsername());
            var response = AdminUserCallsHelper.getUserByUsername(accessToken, testUser.getUsername());
            LOGGER.info("Validating response for attempt to get user by username '{}':\n{}", testUser.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_GetUserByUsername_InvalidInputs() {
        var reader = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to get user by invalid username: '{}'", entry);
            var response = AdminUserCallsHelper.getUserByUsername(accessToken, entry);
            LOGGER.info("Validating response for attempt to get user by invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found with username: '" + entry + "'"));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to get user by non-existing username '{}'", "non_existing_user_" + uniqueString);
        var response = AdminUserCallsHelper.getUserByUsername(accessToken, "non_existing_user_" + uniqueString);
        LOGGER.info("Validating response for attempt to get user by non-existing username '{}':\n{}", "non_existing_user_" + uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with username: '" + "non_existing_user_" + uniqueString + "'"));
    }

    @Test
    public void test_GetUserByEmail_UsingUsersWhoAreAllowedToRead() {
        var readers = new HashSet<UserDto>();
        readers.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AreAllowedTo_Read_Users()));
        for (var role : usersWithTheseRoles_AreAllowedTo_Read_Users()) {
            readers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users();
        roles.addAll(usersWithTheseRoles_AreAllowedTo_Read_Users());
        readers.add(DtosHelper.createRandomUserDto(roles));
        var testUser = DtosHelper.createRandomUserDto();
        readers.add(testUser);
        createTestUsers(readers);
        readers.remove(testUser);
        for (var reader : readers) {
            var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
            LOGGER.info("Attempting to get user by email '{}' using user '{}'", testUser.getEmail(), reader.getUsername());
            var response = AdminUserCallsHelper.getUserByEmail(accessToken, testUser.getEmail());
            LOGGER.info("Validating response for attempt to get user by email '{}':\n{}", testUser.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("email", equalTo(testUser.getEmail()));
        }
    }

    @Test
    public void test_GetUserByEmail_UsingUsersWhoAreNotAllowedToRead() {
        var readers = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            readers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(readers);
        var testUser = DtosHelper.createRandomUserDto();
        for (var reader : readers) {
            var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
            LOGGER.info("Attempting to get user by email '{}' using user '{}'", testUser.getEmail(), reader.getUsername());
            var response = AdminUserCallsHelper.getUserByEmail(accessToken, testUser.getEmail());
            LOGGER.info("Validating response for attempt to get user by email '{}':\n{}", testUser.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_GetUserByEmail_InvalidInputs() {
        var reader = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to get user by invalid email: '{}'", entry);
            var response = AdminUserCallsHelper.getUserByEmail(accessToken, entry);
            LOGGER.info("Validating response for attempt to get user by invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found with email: '" + entry + "'"));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to get user by non-existing email '{}'", "non_existing_user_" + uniqueString + "@example.com");
        var response = AdminUserCallsHelper.getUserByEmail(accessToken, "non_existing_user_" + uniqueString + "@example.com");
        LOGGER.info("Validating response for attempt to get user by non-existing email '{}':\n{}", "non_existing_user_" + uniqueString + "@example.com", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with email: '" + "non_existing_user_" + uniqueString + "@example.com'"));
    }

    @Test
    public void test_GetUser_UsingUsersWhoAreAllowedToRead() {
        var readers = new HashSet<UserDto>();
        readers.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AreAllowedTo_Read_Users()));
        for (var role : usersWithTheseRoles_AreAllowedTo_Read_Users()) {
            readers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users();
        roles.addAll(usersWithTheseRoles_AreAllowedTo_Read_Users());
        readers.add(DtosHelper.createRandomUserDto(roles));
        var testUser = DtosHelper.createRandomUserDto();
        readers.add(testUser);
        createTestUsers(readers);
        readers.remove(testUser);
        var i = 0;
        for (var reader : readers) {
            var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
            LOGGER.info("Attempting to get user: '{}' using user '{}'", i % 2 == 0 ? testUser.getUsername() : testUser.getEmail(), reader.getUsername());
            var response = AdminUserCallsHelper.getUser(accessToken, i % 2 == 0 ? testUser.getUsername() : testUser.getEmail());
            LOGGER.info("Validating response for attempt to get user: '{}'\n{}", i % 2 == 0 ? testUser.getUsername() : testUser.getEmail(), response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("username", equalTo(testUser.getUsername()))
                    .body("email", equalTo(testUser.getEmail()));
            i++;
        }
    }

    @Test
    public void test_GetUser_UsingUsersWhoAreNotAllowedToRead() {
        var readers = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            readers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(readers);
        var testUser = DtosHelper.createRandomUserDto();
        for (var reader : readers) {
            var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
            LOGGER.info("Attempting to get user: '{}' using user '{}'", testUser.getUsername(), reader.getUsername());
            var response = AdminUserCallsHelper.getUser(accessToken, testUser.getUsername());
            LOGGER.info("Validating response for attempt to get user: '{}'\n{}", testUser.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_GetUser_InvalidInputs() {
        var reader = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to get user by invalid username: '{}'", entry);
            var response = AdminUserCallsHelper.getUser(accessToken, entry);
            LOGGER.info("Validating response for attempt to get user by invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to get user by invalid email: '{}'", entry);
            var response = AdminUserCallsHelper.getUser(accessToken, entry);
            LOGGER.info("Validating response for attempt to get user by invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to get user by non-existing username '{}'", "non_existing_user_" + uniqueString);
        var response = AdminUserCallsHelper.getUser(accessToken, "non_existing_user_" + uniqueString);
        LOGGER.info("Validating response for attempt to get user by non-existing username '{}':\n{}", "non_existing_user_" + uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with username: '" + "non_existing_user_" + uniqueString + "'"));
        LOGGER.info("Attempting to get user by non-existing email '{}'", "non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        response = AdminUserCallsHelper.getUser(accessToken, "non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Validating response for attempt to get user by non-existing email '{}':\n{}", "non_existing_user_" + uniqueString.toLowerCase() + "@example.com", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with email: '" + "non_existing_user_" + uniqueString.toLowerCase() + "@example.com'"));
    }

    @Test
    public void test_GetUsers_UsingUsersWhoAreAllowedToRead() {
        var readers = new HashSet<UserDto>();
        readers.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AreAllowedTo_Read_Users()));
        for (var role : usersWithTheseRoles_AreAllowedTo_Read_Users()) {
            readers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users();
        roles.addAll(usersWithTheseRoles_AreAllowedTo_Read_Users());
        readers.add(DtosHelper.createRandomUserDto(roles));
        var testUser = DtosHelper.createRandomUserDto();
        readers.add(testUser);
        createTestUsers(readers);
        readers.remove(testUser);
        for (var reader : readers) {
            var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
            LOGGER.info("Attempting to get users using user '{}'", reader.getUsername());
            var response = AdminUserCallsHelper.getUsers(accessToken, Set.of(testUser.getUsername()));
            LOGGER.info("Validating response for attempt to get users using user '{}':\n{}", reader.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("", hasSize(1))
                    .body("[0].username", equalTo(testUser.getUsername()))
                    .body("[0].email", equalTo(testUser.getEmail()));
        }
    }

    @Test
    public void test_GetUsers_UsingUsersWhoAreNotAllowedToRead() {
        var readers = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            readers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(readers);
        var testUser = DtosHelper.createRandomUserDto();
        for (var reader : readers) {
            var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
            LOGGER.info("Attempting to get users using user '{}'", reader.getUsername());
            var response = AdminUserCallsHelper.getUsers(accessToken, Set.of(testUser.getUsername(), testUser.getEmail()));
            LOGGER.info("Validating response for attempt to get users using user '{}':\n{}", reader.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_GetUsers_InvalidInputs() {
        var reader = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(reader.getUsername(), reader.getPassword());
        var invalidInputs = new HashSet<>(InvalidInputsHelper.invalidUsernames());
        invalidInputs.addAll(InvalidInputsHelper.invalidEmails());
        invalidInputs.add(reader.getUsername());
        invalidInputs.add(reader.getEmail());
        LOGGER.info("Attempting to get users with invalid inputs: {}", ToJsonForLoggingUtil.toJson(invalidInputs));
        var response = AdminUserCallsHelper.getUsers(accessToken, invalidInputs);
        LOGGER.info("Validating response for attempt to get users with invalid inputs:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("users_found_with_these_usernames_or_emails", not(empty()));
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        invalidInputs.clear();
        invalidInputs.add("non_existing_user_" + uniqueString);
        invalidInputs.add("non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        LOGGER.info("Attempting to get users with non-existing usernames and emails: {}", ToJsonForLoggingUtil.toJson(invalidInputs));
        response = AdminUserCallsHelper.getUsers(accessToken, invalidInputs);
        LOGGER.info("Validating response for attempt to get users with non-existing usernames and emails:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400)
                .body("not_found_usernames", not(empty()))
                .body("not_found_emails", not(empty()));
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleSuperAdmin() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCanBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCanBeUpdatedBySuperAdmin) {
            var updateInput = DtosHelper.createRandomUserDto(Set.of());
            TEST_USERS.add(updateInput);
            LOGGER.info("Using super admin user: '{}' to update user: '{}' with input:\n{}", updater.getUsername(), userToBeUpdated.getUsername(), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, userToBeUpdated.getUsername(), updateInput);
            LOGGER.info("Validating response for updating user: '{}'\n{}", userToBeUpdated.getUsername(), response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfUserUpdate(response, updater, userToBeUpdated, updateInput);
        }
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleAdmin() {
        var updater = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCanBeUpdatedByAdmin = new HashSet<UserDto>();
        usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCanBeUpdatedByAdmin) {
            var updateInput = DtosHelper.createRandomUserDto(Set.of());
            TEST_USERS.add(updateInput);
            LOGGER.info("Using admin user: '{}' to update user: '{}' with input:\n{}", updater.getUsername(), userToBeUpdated.getUsername(), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, userToBeUpdated.getUsername(), updateInput);
            LOGGER.info("Validating response for updating user: '{}'\n{}", userToBeUpdated.getUsername(), response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfUserUpdate(response, updater, userToBeUpdated, updateInput);
        }
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleManageUsers() {
        var updater = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCanBeUpdatedByManageUsers = new HashSet<UserDto>();
        usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCanBeUpdatedByManageUsers) {
            var updateInput = DtosHelper.createRandomUserDto(Set.of());
            TEST_USERS.add(updateInput);
            LOGGER.info("Using manage users user: '{}' to update user: '{}' with input:\n{}", updater.getUsername(), userToBeUpdated.getUsername(), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, userToBeUpdated.getUsername(), updateInput);
            LOGGER.info("Validating response for updating user: '{}'\n{}", userToBeUpdated.getUsername(), response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfUserUpdate(response, updater, userToBeUpdated, updateInput);
        }
    }

    @Test
    public void test_UpdateUser_UsingUsersWhoAreNotAllowedToUpdate() {
        var updaters = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            updaters.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(updaters);
        var testUser = DtosHelper.createRandomUserDto();
        for (var updater : updaters) {
            var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
            LOGGER.info("Attempting to update user: '{}' using user '{}'", testUser.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUser);
            LOGGER.info("Validating response for attempt to update user: '{}'\n{}", testUser.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_UpdateUser_InvalidInputs() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        var testUpdateInput = new UserDto();
        LOGGER.info("Attempting to update your own user: '{}' with input:\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(testUpdateInput));
        var response = AdminUserCallsHelper.updateUser(accessToken, updater.getUsername(), testUpdateInput);
        LOGGER.info("Validating response for attempt to update your own user: '{}'\n{}", updater.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString(updater.getUsername() + "(You cannot modify your own account using this endpoint)"));
        LOGGER.info("Attempting to update your own user by email: '{}' with input:\n{}", updater.getEmail(), ToJsonForLoggingUtil.toJson(testUpdateInput));
        response = AdminUserCallsHelper.updateUser(accessToken, updater.getEmail(), testUpdateInput);
        LOGGER.info("Validating response for attempt to update your own user by email: '{}'\n{}", updater.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString(updater.getEmail() + "(You cannot modify your own account using this endpoint)"));
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            testUpdateInput.setUsername(entry);
            LOGGER.info("Attempting to update user by invalid username: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testUpdateInput));
            response = AdminUserCallsHelper.updateUser(accessToken, entry, testUpdateInput);
            LOGGER.info("Validating response for attempt to update user by invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            testUpdateInput.setEmail(entry);
            LOGGER.info("Attempting to update user by invalid email: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testUpdateInput));
            response = AdminUserCallsHelper.updateUser(accessToken, entry, testUpdateInput);
            LOGGER.info("Validating response for attempt to update user by invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        LOGGER.info("Attempting to update user by non-existing username '{}'", "non_existing_user_" + uniqueString);
        response = AdminUserCallsHelper.updateUser(accessToken, "non_existing_user_" + uniqueString, testUpdateInput);
        LOGGER.info("Validating response for attempt to update user by non-existing username '{}':\n{}", "non_existing_user_" + uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with username: '" + "non_existing_user_" + uniqueString + "'"));
        LOGGER.info("Attempting to update user by non-existing email '{}'", "non_existing_user_" + uniqueString.toLowerCase() + "@example.com");
        response = AdminUserCallsHelper.updateUser(accessToken, "non_existing_user_" + uniqueString.toLowerCase() + "@example.com", testUpdateInput);
        LOGGER.info("Validating response for attempt to update user by non-existing email '{}':\n{}", "non_existing_user_" + uniqueString.toLowerCase() + "@example.com", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found with email: '" + "non_existing_user_" + uniqueString.toLowerCase() + "@example.com'"));
        var testUser = createTestUser();
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUpdateInput.setFirstName(entry);
            LOGGER.info("Attempting to update user: '{}' with invalid first name: '{}'\n{}", testUser.getUsername(), entry, ToJsonForLoggingUtil.toJson(testUpdateInput));
            response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with invalid first name: '{}'\n{}", testUser.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUpdateInput.setFirstName("ValidFirstName");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUpdateInput.setMiddleName(entry);
            LOGGER.info("Attempting to update user: '{}' with invalid middle name: '{}'\n{}", testUser.getUsername(), entry, ToJsonForLoggingUtil.toJson(testUpdateInput));
            response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with invalid middle name: '{}'\n{}", testUser.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUpdateInput.setMiddleName("ValidMiddleName");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUpdateInput.setLastName(entry);
            LOGGER.info("Attempting to update user: '{}' with invalid last name: '{}'\n{}", testUser.getUsername(), entry, ToJsonForLoggingUtil.toJson(testUpdateInput));
            response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with invalid last name: '{}'\n{}", testUser.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUpdateInput.setLastName("ValidLastName");
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            testUpdateInput.setPassword(entry);
            LOGGER.info("Attempting to update user: '{}' with invalid password: '{}'\n{}", testUser.getUsername(), entry, ToJsonForLoggingUtil.toJson(testUpdateInput));
            response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with invalid password: '{}'\n{}", testUser.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUpdateInput.setPassword("ValidPassword123!");
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            testUpdateInput.setEmail(entry);
            LOGGER.info("Attempting to update user: '{}' with invalid email: '{}'\n{}", testUser.getUsername(), entry, ToJsonForLoggingUtil.toJson(testUpdateInput));
            response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with invalid email: '{}'\n{}", testUser.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUpdateInput.setEmail("user_" + uniqueString.toLowerCase() + "@example.com");
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            testUpdateInput.setUsername(entry);
            LOGGER.info("Attempting to update user: '{}' with invalid username: '{}'\n{}", testUser.getUsername(), entry, ToJsonForLoggingUtil.toJson(testUpdateInput));
            response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with invalid username: '{}'\n{}", testUser.getUsername(), entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUpdateInput.setUsername("AutoTestUser_" + uniqueString);
        testUpdateInput.setEmail(updater.getEmail());
        LOGGER.info("Attempting to update user: '{}' with email that is already used by other user: '{}'\n{}", testUser.getUsername(), updater.getEmail(), ToJsonForLoggingUtil.toJson(testUpdateInput));
        response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
        LOGGER.info("Validating response for attempt to update to update user: '{}' with email that is already used by other user: '{}'\n{}", testUser.getUsername(), updater.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        testUpdateInput.setEmail("user_" + uniqueString.toLowerCase() + "@example.com");
        testUpdateInput.setUsername(updater.getUsername());
        LOGGER.info("Attempting to update user: '{}' with username that is already used by other user: '{}'\n{}", testUser.getUsername(), updater.getUsername(), ToJsonForLoggingUtil.toJson(testUpdateInput));
        response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
        LOGGER.info("Validating response for attempt to update to update user: '{}' with username that is already used by other user: '{}'\n{}", testUser.getUsername(), updater.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        testUpdateInput.setUsername("AutoTestUser_" + uniqueString);
        testUpdateInput.setRoles(Set.of("ROLE_INVALID_" + uniqueString));
        LOGGER.info("Attempting to update user: '{}' with invalid role: 'ROLE_INVALID_{}'\n{}", testUser.getUsername(), uniqueString, ToJsonForLoggingUtil.toJson(testUpdateInput));
        response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), testUpdateInput);
        LOGGER.info("Validating response for attempt to update user: '{}' with invalid role: 'ROLE_INVALID_{}'\n{}", testUser.getUsername(), uniqueString, response.getBody().asPrettyString());
        response.then().statusCode(400).body("non_existing_roles", not(empty()));
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleSuperAdmin_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCannotBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedBySuperAdmin);
        var updateInput = DtosHelper.createRandomUserDto(Set.of());
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedBySuperAdmin) {
            LOGGER.info("Attempting to update user: '{}' using super admin user: '{}'\n{}", userToBeUpdated.getUsername(), updater.getUsername(), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, userToBeUpdated.getUsername(), updateInput);
            LOGGER.info("Validating response for attempt to update user: '{}'\n{}", userToBeUpdated.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleAdmin_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCannotBeUpdatedByAdmin = new HashSet<UserDto>();
        usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedByAdmin);
        var updateInput = DtosHelper.createRandomUserDto(Set.of());
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedByAdmin) {
            LOGGER.info("Attempting to update user: '{}' using admin user: '{}'\n{}", userToBeUpdated.getUsername(), updater.getUsername(), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, userToBeUpdated.getUsername(), updateInput);
            LOGGER.info("Validating response for attempt to update user: '{}'\n{}", userToBeUpdated.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleManageUsers_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCannotBeUpdatedByManageUsers = new HashSet<UserDto>();
        usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedByManageUsers);
        var updateInput = DtosHelper.createRandomUserDto(Set.of());
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedByManageUsers) {
            LOGGER.info("Attempting to update user: '{}' using manage users user: '{}'\n{}", userToBeUpdated.getUsername(), updater.getUsername(), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, userToBeUpdated.getUsername(), updateInput);
            LOGGER.info("Validating response for attempt to update user: '{}'\n{}", userToBeUpdated.getUsername(), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleSuperAdmin_NotAllowedToGiveCertainRolesToUpdatableUsers() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var testUser = createTestUser();
        var setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers = new HashSet<Set<String>>();
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(Set.of(role));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(roles);
        var updateInput = DtosHelper.createRandomUserDto();
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var rolesSet : setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers) {
            updateInput.setRoles(rolesSet);
            LOGGER.info("Attempting to update user: '{}' with roles: '{}'\n{}", testUser.getUsername(), ToJsonForLoggingUtil.toJson(rolesSet), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), updateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with roles: '{}'\n{}", testUser.getUsername(), ToJsonForLoggingUtil.toJson(rolesSet), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleAdmin_NotAllowedToGiveCertainRolesToUpdatableUsers() {
        var updater = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var testUser = createTestUser();
        var setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers = new HashSet<Set<String>>();
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(Set.of(role));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(roles);
        var updateInput = DtosHelper.createRandomUserDto();
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var rolesSet : setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers) {
            updateInput.setRoles(rolesSet);
            LOGGER.info("Attempting to update user: '{}' with roles: '{}'\n{}", testUser.getUsername(), ToJsonForLoggingUtil.toJson(rolesSet), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), updateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with roles: '{}'\n{}", testUser.getUsername(), ToJsonForLoggingUtil.toJson(rolesSet), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_UpdateUser_UsingUserWithRoleManageUsers_NotAllowedToGiveCertainRolesToUpdatableUsers() {
        var updater = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var testUser = createTestUser();
        var setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers = new HashSet<Set<String>>();
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(Set.of(role));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(roles);
        var updateInput = DtosHelper.createRandomUserDto();
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var rolesSet : setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers) {
            updateInput.setRoles(rolesSet);
            LOGGER.info("Attempting to update user: '{}' with roles: '{}'\n{}", testUser.getUsername(), ToJsonForLoggingUtil.toJson(rolesSet), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUser(accessToken, testUser.getUsername(), updateInput);
            LOGGER.info("Validating response for attempt to update user: '{}' with roles: '{}'\n{}", testUser.getUsername(), ToJsonForLoggingUtil.toJson(rolesSet), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleSuperAdmin() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCanBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedBySuperAdmin);
        var updateInputs = new HashSet<UserDto>();
        for (var userToBeUpdated : usersThatCanBeUpdatedBySuperAdmin) {
            var updateInput = DtosHelper.createRandomUserDto(Set.of());
            updateInput.setUsername(userToBeUpdated.getUsername());
            updateInputs.add(updateInput);
        }
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        LOGGER.info("Using super admin user: '{}' to update users with inputs:\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(updateInputs));
        var response = AdminUserCallsHelper.updateUsers(accessToken, updateInputs);
        LOGGER.info("Validating response for updating users:\n{}", response.getBody().asPrettyString());
        ResponseValidatorHelper.validateResponseOfUsersUpdate(response, updater, usersThatCanBeUpdatedBySuperAdmin, updateInputs, "");
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleAdmin() {
        var updater = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCanBeUpdatedByAdmin = new HashSet<UserDto>();
        usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedByAdmin);
        var updateInputs = new HashSet<UserDto>();
        for (var userToBeUpdated : usersThatCanBeUpdatedByAdmin) {
            var updateInput = DtosHelper.createRandomUserDto(Set.of());
            updateInput.setUsername(userToBeUpdated.getUsername());
            updateInputs.add(updateInput);
        }
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        LOGGER.info("Using admin user: '{}' to update users with inputs:\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(updateInputs));
        var response = AdminUserCallsHelper.updateUsers(accessToken, updateInputs);
        LOGGER.info("Validating response for updating users:\n{}", response.getBody().asPrettyString());
        ResponseValidatorHelper.validateResponseOfUsersUpdate(response, updater, usersThatCanBeUpdatedByAdmin, updateInputs, "");
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleManageUsers() {
        var updater = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCanBeUpdatedByManageUsers = new HashSet<UserDto>();
        usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedByManageUsers);
        var updateInputs = new HashSet<UserDto>();
        for (var userToBeUpdated : usersThatCanBeUpdatedByManageUsers) {
            var updateInput = DtosHelper.createRandomUserDto(Set.of());
            updateInput.setUsername(userToBeUpdated.getUsername());
            updateInputs.add(updateInput);
        }
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        LOGGER.info("Using manage users user: '{}' to update users with inputs:\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(updateInputs));
        var response = AdminUserCallsHelper.updateUsers(accessToken, updateInputs);
        LOGGER.info("Validating response for updating users:\n{}", response.getBody().asPrettyString());
        ResponseValidatorHelper.validateResponseOfUsersUpdate(response, updater, usersThatCanBeUpdatedByManageUsers, updateInputs, "");
    }

    @Test
    public void test_UpdateUsers_UsingUsersWhoAreNotAllowedToUpdate() {
        var updaters = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            updaters.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(updaters);
        var updateInput = DtosHelper.createRandomUserDto(Set.of());
        for (var updater : updaters) {
            var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
            LOGGER.info("Attempting to update users:\n{}\nusing user: '{}'", ToJsonForLoggingUtil.toJson(Set.of(updateInput)), updater.getUsername());
            var response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(updateInput));
            LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_UpdateUsers_InvalidInputs() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var testUser = new UserDto();
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        LOGGER.info("Attempting to update users with null username of any user in request:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testUser)));
        var response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to update users with null username of any user in request:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("users_not_found_with_these_usernames", not(empty()));
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            testUser.setUsername(entry);
            LOGGER.info("Attempting to update users with invalid username: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testUser)));
            response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to update users with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("users_not_found_with_these_usernames", not(empty()));
        }
        var testUser1 = DtosHelper.createRandomUserDto();
        var testUser2 = DtosHelper.createRandomUserDto();
        testUser2.setUsername(testUser1.getUsername());
        testUser2.setEmail(testUser1.getEmail());
        LOGGER.info("Attempting to update users with duplicate usernames/emails in request:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testUser1, testUser2)));
        response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser1, testUser2));
        LOGGER.info("Validating response for attempt to update users with duplicate usernames/emails in request:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400)
                .body("duplicate_usernames_in_request", not(empty()))
                .body("duplicate_emails_in_request", not(empty()));
        LOGGER.info("Attempting to update your own user using this endpoint:\n{}", ToJsonForLoggingUtil.toJson(Set.of(updater)));
        response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(updater));
        LOGGER.info("Validating response for attempt to update your own user using this endpoint:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_cannot_update_your_own_account_using_this_endpoint", not(empty()));
        testUser1.setEmail(updater.getEmail());
        LOGGER.info("Attempting to update users with email that is already used by other user: '{}'\n{}", updater.getEmail(), ToJsonForLoggingUtil.toJson(Set.of(testUser1)));
        response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser1));
        LOGGER.info("Validating response for attempt to update users with email that is already used by other user: '{}'\n{}", updater.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("emails_that_already_taken_by_other_users", not(empty()));
        testUser1.setEmail(testUser2.getEmail());
        LOGGER.info("Attempting to update any non-existing user in request:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testUser1)));
        response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser1));
        LOGGER.info("Validating response for attempt to update any non-existing user in request:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_usernames", not(empty()));
        var existingTestUser = createTestUser();
        testUser = new UserDto();
        testUser.setUsername(existingTestUser.getUsername());
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setFirstName(entry);
            LOGGER.info("Attempting to update users:\n{}\nwith invalid first name: '{}'", ToJsonForLoggingUtil.toJson(Set.of(testUser)), entry);
            response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to update users with invalid first name:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setFirstName("ValidFirstName");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setMiddleName(entry);
            LOGGER.info("Attempting to update users:\n{}\nwith invalid middle name: '{}'", ToJsonForLoggingUtil.toJson(Set.of(testUser)), entry);
            response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to update users with invalid middle name:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setMiddleName("ValidMiddleName");
        for (var entry : InvalidInputsHelper.invalidNames()) {
            testUser.setLastName(entry);
            LOGGER.info("Attempting to update users:\n{}\nwith invalid last name: '{}'", ToJsonForLoggingUtil.toJson(Set.of(testUser)), entry);
            response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to update users with invalid last name:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setLastName("ValidLastName");
        for (var entry : InvalidInputsHelper.invalidPasswords()) {
            testUser.setPassword(entry);
            LOGGER.info("Attempting to update users:\n{}\nwith invalid password: '{}'", ToJsonForLoggingUtil.toJson(Set.of(testUser)), entry);
            response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to update users with invalid password:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setPassword("ValidPassword123!");
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            testUser.setEmail(entry);
            LOGGER.info("Attempting to update users:\n{}\nwith invalid email: '{}'", ToJsonForLoggingUtil.toJson(Set.of(testUser)), entry);
            response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser));
            LOGGER.info("Validating response for attempt to update users with invalid email:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testUser.setEmail(testUser2.getEmail());
        testUser.setRoles(Set.of("ROLE_INVALID_" + updater.getUsername()));
        LOGGER.info("Attempting to update users:\n{}\nwith invalid role: 'ROLE_INVALID_{}'", ToJsonForLoggingUtil.toJson(Set.of(testUser)), updater.getUsername());
        response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(testUser));
        LOGGER.info("Validating response for attempt to update users with invalid role: 'ROLE_INVALID_{}'\n{}", updater.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("non_existing_roles", not(empty()));
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleSuperAdmin_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCannotBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedBySuperAdmin) {
            LOGGER.info("Attempting to update users using super admin user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(Set.of(userToBeUpdated)));
            var response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(userToBeUpdated));
            LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
        }
        LOGGER.info("Attempting to update users using super admin user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(usersThatCannotBeUpdatedBySuperAdmin));
        var response = AdminUserCallsHelper.updateUsers(accessToken, usersThatCannotBeUpdatedBySuperAdmin);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
        var userThatCanBeUpdatedBySuperAdmin = createTestUser();
        usersThatCannotBeUpdatedBySuperAdmin.add(userThatCanBeUpdatedBySuperAdmin);
        LOGGER.info("Attempting to update users using super admin user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(usersThatCannotBeUpdatedBySuperAdmin));
        response = AdminUserCallsHelper.updateUsers(accessToken, usersThatCannotBeUpdatedBySuperAdmin);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleAdmin_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCannotBeUpdatedByAdmin = new HashSet<UserDto>();
        usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedByAdmin) {
            LOGGER.info("Attempting to update users using admin user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(Set.of(userToBeUpdated)));
            var response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(userToBeUpdated));
            LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
        }
        LOGGER.info("Attempting to update users using admin user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(usersThatCannotBeUpdatedByAdmin));
        var response = AdminUserCallsHelper.updateUsers(accessToken, usersThatCannotBeUpdatedByAdmin);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
        var userThatCanBeUpdatedByAdmin = createTestUser();
        usersThatCannotBeUpdatedByAdmin.add(userThatCanBeUpdatedByAdmin);
        LOGGER.info("Attempting to update users using admin user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(usersThatCannotBeUpdatedByAdmin));
        response = AdminUserCallsHelper.updateUsers(accessToken, usersThatCannotBeUpdatedByAdmin);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleManageUsers_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCannotBeUpdatedByManageUsers = new HashSet<UserDto>();
        usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedByManageUsers) {
            LOGGER.info("Attempting to update users using manage users user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(Set.of(userToBeUpdated)));
            var response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(userToBeUpdated));
            LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
        }
        LOGGER.info("Attempting to update users using manage users user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(usersThatCannotBeUpdatedByManageUsers));
        var response = AdminUserCallsHelper.updateUsers(accessToken, usersThatCannotBeUpdatedByManageUsers);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
        var userThatCanBeUpdatedByManageUsers = createTestUser();
        usersThatCannotBeUpdatedByManageUsers.add(userThatCanBeUpdatedByManageUsers);
        LOGGER.info("Attempting to update users using manage users user: '{}'\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(usersThatCannotBeUpdatedByManageUsers));
        response = AdminUserCallsHelper.updateUsers(accessToken, usersThatCannotBeUpdatedByManageUsers);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_cannot_modify_users_with_these_roles", not(empty()));
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleSuperAdmin_NotAllowedToGiveCertainRolesToUpdatableUsers() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers = new HashSet<Set<String>>();
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(Set.of(role));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(roles);
        var updateInput = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var rolesSet : setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers) {
            updateInput.setRoles(rolesSet);
            LOGGER.info("Attempting to update users with roles: '{}'\n{}", ToJsonForLoggingUtil.toJson(rolesSet), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(updateInput));
            LOGGER.info("Validating response for attempt to update users with roles: '{}'\n{}", ToJsonForLoggingUtil.toJson(rolesSet), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
        var userThatCanBeUpdatedBySuperAdmin = createTestUser();
        var setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedBySuperAdminAndUsersThatCannotBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedBySuperAdminAndUsersThatCannotBeUpdatedBySuperAdmin.add(userThatCanBeUpdatedBySuperAdmin);
        setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedBySuperAdminAndUsersThatCannotBeUpdatedBySuperAdmin.add(updateInput);
        LOGGER.info("Attempting to update users:\n{}", ToJsonForLoggingUtil.toJson(setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedBySuperAdminAndUsersThatCannotBeUpdatedBySuperAdmin));
        var response = AdminUserCallsHelper.updateUsers(accessToken, setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedBySuperAdminAndUsersThatCannotBeUpdatedBySuperAdmin);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleAdmin_NotAllowedToGiveCertainRolesToUpdatableUsers() {
        var updater = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers = new HashSet<Set<String>>();
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(Set.of(role));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(roles);
        var updateInput = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var rolesSet : setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers) {
            updateInput.setRoles(rolesSet);
            LOGGER.info("Attempting to update users with roles: '{}'\n{}", ToJsonForLoggingUtil.toJson(rolesSet), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(updateInput));
            LOGGER.info("Validating response for attempt to update users with roles: '{}'\n{}", ToJsonForLoggingUtil.toJson(rolesSet), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
        var userThatCanBeUpdatedByAdmin = createTestUser();
        var setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByAdminAndUsersThatCannotBeUpdatedByAdmin = new HashSet<UserDto>();
        setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByAdminAndUsersThatCannotBeUpdatedByAdmin.add(userThatCanBeUpdatedByAdmin);
        setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByAdminAndUsersThatCannotBeUpdatedByAdmin.add(updateInput);
        LOGGER.info("Attempting to update users:\n{}", ToJsonForLoggingUtil.toJson(setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByAdminAndUsersThatCannotBeUpdatedByAdmin));
        var response = AdminUserCallsHelper.updateUsers(accessToken, setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByAdminAndUsersThatCannotBeUpdatedByAdmin);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
    }

    @Test
    public void test_UpdateUsers_UsingUserWithRoleManageUsers_NotAllowedToGiveCertainRolesToUpdatableUsers() {
        var updater = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers = new HashSet<Set<String>>();
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(Set.of(role));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers.add(roles);
        var updateInput = createTestUser();
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var rolesSet : setOfSetOfRolesNotAllowedToBeGivenToUpdatableUsers) {
            updateInput.setRoles(rolesSet);
            LOGGER.info("Attempting to update users with roles: '{}'\n{}", ToJsonForLoggingUtil.toJson(rolesSet), ToJsonForLoggingUtil.toJson(updateInput));
            var response = AdminUserCallsHelper.updateUsers(accessToken, Set.of(updateInput));
            LOGGER.info("Validating response for attempt to update users with roles: '{}'\n{}", ToJsonForLoggingUtil.toJson(rolesSet), response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
        }
        var userThatCanBeUpdatedByManageUsers = createTestUser();
        var setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByManageUsersAndUsersThatCannotBeUpdatedByManageUsers = new HashSet<UserDto>();
        setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByManageUsersAndUsersThatCannotBeUpdatedByManageUsers.add(userThatCanBeUpdatedByManageUsers);
        setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByManageUsersAndUsersThatCannotBeUpdatedByManageUsers.add(updateInput);
        LOGGER.info("Attempting to update users:\n{}", ToJsonForLoggingUtil.toJson(setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByManageUsersAndUsersThatCannotBeUpdatedByManageUsers));
        var response = AdminUserCallsHelper.updateUsers(accessToken, setOfUsersThatHaveBothTypeOfUsersThatCanBeUpdatedByManageUsersAndUsersThatCannotBeUpdatedByManageUsers);
        LOGGER.info("Validating response for attempt to update users:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("you_are_not_allowed_to_assign_these_roles", not(empty()));
    }

    private Set<String> usersWithTheseRoles_NotAllowedTo_ReadPermission() {
        var rolesSet = new HashSet<String>();
        rolesSet.add(Roles.ROLE_MANAGE_USERS.name());
        rolesSet.add(Roles.ROLE_MANAGE_ROLES.name());
        return rolesSet;
    }

    private Set<String> usersWithTheseRoles_AllowedTo_ReadPermission() {
        return Set.of(
                Roles.ROLE_SUPER_ADMIN.name(),
                Roles.ROLE_ADMIN.name(),
                Roles.ROLE_MANAGE_PERMISSIONS.name()
        );
    }

    @Test
    public void test_GetPermission_UsingUsersWithRolesAllowedToReadPermission() {
        var usersThatCanReadPermission = new HashSet<UserDto>();
        usersThatCanReadPermission.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_ReadPermission()));
        for (var role : usersWithTheseRoles_AllowedTo_ReadPermission()) {
            usersThatCanReadPermission.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanReadPermission);
        for (var user : usersThatCanReadPermission) {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Using user: '{}' to get permission: '{}'", user.getUsername(), Permissions.CAN_CREATE_USER.name());
            var response = AdminUserCallsHelper.getPermission(accessToken, Permissions.CAN_CREATE_USER.name());
            LOGGER.info("Validating response to get permission: '{}'\n{}", Permissions.CAN_CREATE_USER.name(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("permissionName", equalTo(Permissions.CAN_CREATE_USER.name()));
        }
    }

    @Test
    public void test_GetPermission_UsingUsersWithRolesNotAllowedToReadPermission() {
        var usersThatCannotReadPermission = new HashSet<UserDto>();
        usersThatCannotReadPermission.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_ReadPermission()));
        for (var role : usersWithTheseRoles_NotAllowedTo_ReadPermission()) {
            usersThatCannotReadPermission.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotReadPermission);
        for (var user : usersThatCannotReadPermission) {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Attempting to get permission: '{}' using user: '{}'", Permissions.CAN_CREATE_USER.name(), user.getUsername());
            var response = AdminUserCallsHelper.getPermission(accessToken, Permissions.CAN_CREATE_USER.name());
            LOGGER.info("Validating response for attempt to get permission: '{}'\n{}", Permissions.CAN_CREATE_USER.name(), response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_GetPermission_InvalidInputs() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var entry : InvalidInputsHelper.invalidPermissionNames()) {
            LOGGER.info("Attempting to get permission with permission name: '{}'", entry);
            var response = AdminUserCallsHelper.getPermission(accessToken, entry);
            LOGGER.info("Validating response for attempt to get permission with permission name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Permission not found: '" + entry + "'"));
        }
        LOGGER.info("Attempting to get permission with non-existing permission name: 'INVALID_PERMISSION_NAME_{}'", updater.getUsername());
        var response = AdminUserCallsHelper.getPermission(accessToken, "INVALID_PERMISSION_NAME_" + updater.getUsername());
        LOGGER.info("Validating response for attempt to get permission with non-existing permission name: 'INVALID_PERMISSION_NAME_{}'\n{}", updater.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Permission not found: 'INVALID_PERMISSION_NAME_" + updater.getUsername() + "'"));
    }

    @Test
    public void test_GetPermissions_UsingUsersWithRolesAllowedToReadPermissions() {
        var usersThatCanReadPermissions = new HashSet<UserDto>();
        usersThatCanReadPermissions.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_ReadPermission()));
        for (var role : usersWithTheseRoles_AllowedTo_ReadPermission()) {
            usersThatCanReadPermissions.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanReadPermissions);
        var setOfExistingPermissions = Set.of(Permissions.CAN_READ_USER.name(), Permissions.CAN_CREATE_USER.name());
        for (var user : usersThatCanReadPermissions) {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Using user: '{}' to get permissions: '{}'", user.getUsername(), ToJsonForLoggingUtil.toJson(setOfExistingPermissions));
            var response = AdminUserCallsHelper.getPermissions(accessToken, setOfExistingPermissions);
            LOGGER.info("Validating response to get permissions:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("size()", equalTo(setOfExistingPermissions.size()))
                    .body("permissionName", hasItems(
                            Permissions.CAN_READ_USER.name(),
                            Permissions.CAN_CREATE_USER.name()
                    ));
        }
    }

    @Test
    public void test_GetPermissions_UsingUsersWithRolesNotAllowedToReadPermissions() {
        var usersThatCannotReadPermissions = new HashSet<UserDto>();
        usersThatCannotReadPermissions.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_ReadPermission()));
        for (var role : usersWithTheseRoles_NotAllowedTo_ReadPermission()) {
            usersThatCannotReadPermissions.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotReadPermissions);
        for (var user : usersThatCannotReadPermissions) {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Attempting to get permissions: '{}' using user: '{}'", ToJsonForLoggingUtil.toJson(Set.of(Permissions.CAN_CREATE_USER.name())), user.getUsername());
            var response = AdminUserCallsHelper.getPermissions(accessToken, Set.of(Permissions.CAN_CREATE_USER.name()));
            LOGGER.info("Validating response for attempt to get permissions:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_GetPermissions_InvalidInputs() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var entry : InvalidInputsHelper.invalidPermissionNames()) {
            LOGGER.info("Attempting to get permissions: '{}'", Set.of(entry));
            var response = AdminUserCallsHelper.getPermissions(accessToken, Set.of(entry));
            LOGGER.info("Validating response for attempt to get permissions:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("not_found_permissions", not(empty()));
        }
        LOGGER.info("Attempting to get permissions: '{}'", InvalidInputsHelper.invalidPermissionNames());
        var response = AdminUserCallsHelper.getPermissions(accessToken, InvalidInputsHelper.invalidPermissionNames());
        LOGGER.info("Validating response for attempt to get permissions:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_permissions", not(empty()));
        LOGGER.info("Attempting to get permissions: '{}'", Set.of("INVALID_PERMISSION_NAME_" + updater.getUsername()));
        response = AdminUserCallsHelper.getPermissions(accessToken, Set.of("INVALID_PERMISSION_NAME_" + updater.getUsername()));
        LOGGER.info("Validating response for attempt to get permissions:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_permissions", not(empty()));
        LOGGER.info("Attempting to get permissions: '{}'", Set.of("INVALID_PERMISSION_NAME_" + updater.getUsername(), Permissions.CAN_READ_USER.name()));
        response = AdminUserCallsHelper.getPermissions(accessToken, Set.of("INVALID_PERMISSION_NAME_" + updater.getUsername(), Permissions.CAN_READ_USER.name()));
        LOGGER.info("Validating response for attempt to get permissions:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_permissions", not(empty()));
    }

    private Set<String> usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles() {
        var rolesSet = new HashSet<String>();
        rolesSet.add(Roles.ROLE_MANAGE_USERS.name());
        rolesSet.add(Roles.ROLE_MANAGE_PERMISSIONS.name());
        return rolesSet;
    }

    private Set<String> usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles() {
        return Set.of(
                Roles.ROLE_SUPER_ADMIN.name(),
                Roles.ROLE_ADMIN.name(),
                Roles.ROLE_MANAGE_ROLES.name()
        );
    }

    @Test
    public void test_CreateRole_UsingUsersWithRolesAllowedToCreateRoles() {
        var usersThatCanCreateRole = new HashSet<UserDto>();
        usersThatCanCreateRole.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCanCreateRole.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles();
        roles.addAll(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles());
        usersThatCanCreateRole.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCanCreateRole);
        for (var creator : usersThatCanCreateRole) {
            var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
            var roleDto = DtosHelper.createRandomRoleDto();
            TEST_ROLES.add(roleDto);
            LOGGER.info("Using user: '{}' to create role:\n{}", creator.getUsername(), ToJsonForLoggingUtil.toJson(roleDto));
            var response = AdminUserCallsHelper.createRole(accessToken, roleDto);
            LOGGER.info("Validating response to create role:\n{}", response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfRoleCreation(response, creator, roleDto);
        }
    }

    @Test
    public void test_CreateRole_UsingUsersWithRolesNotAllowedToCreateRoles() {
        var usersThatCannotCreateRole = new HashSet<UserDto>();
        usersThatCannotCreateRole.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCannotCreateRole.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotCreateRole);
        var roleDto = DtosHelper.createRandomRoleDto();
        for (var creator : usersThatCannotCreateRole) {
            var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
            LOGGER.info("Attempting to create role:\n{} using user: '{}'", ToJsonForLoggingUtil.toJson(roleDto), creator.getUsername());
            var response = AdminUserCallsHelper.createRole(accessToken, roleDto);
            LOGGER.info("Validating response for attempt to create role:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_CreateRole_InvalidInputs() {
        var creator = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        var roleDto = new RoleDto();
        LOGGER.info("Attempting to create role with null role name:\n{}", ToJsonForLoggingUtil.toJson(roleDto));
        var response = AdminUserCallsHelper.createRole(accessToken, roleDto);
        LOGGER.info("Validating response for attempt to create role with null role name:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidRoleNames()) {
            roleDto.setRoleName(entry);
            LOGGER.info("Attempting to create role with invalid role name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(roleDto));
            response = AdminUserCallsHelper.createRole(accessToken, roleDto);
            LOGGER.info("Validating response for attempt to create role with invalid role name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        var existingRole = createTestRole();
        roleDto.setRoleName(existingRole.getRoleName());
        LOGGER.info("Attempting to create role with existing role name: '{}'\n{}", existingRole.getRoleName(), ToJsonForLoggingUtil.toJson(roleDto));
        response = AdminUserCallsHelper.createRole(accessToken, roleDto);
        LOGGER.info("Validating response for attempt to create role with existing role name: '{}'\n{}", existingRole.getRoleName(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Role: '" + existingRole.getRoleName() + "' already exists"));
        roleDto.setRoleName("AutoTestRole_" + RandomStringUtil.generateRandomStringAlphaNumeric());
        roleDto.setPermissions(Set.of(Permissions.CAN_CREATE_USER.name(), "NON_EXISTING_PERMISSION_" + creator.getUsername()));
        LOGGER.info("Attempting to create role with some or all non-existing permissions: '{}'\n{}", ToJsonForLoggingUtil.toJson(roleDto.getPermissions()), ToJsonForLoggingUtil.toJson(roleDto));
        response = AdminUserCallsHelper.createRole(accessToken, roleDto);
        LOGGER.info("Validating response for attempt to create role with some or all non-existing permissions:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("non_existing_permissions", not(empty()));
    }

    @Test
    public void test_CreateRoles_UsingUsersWithRolesAllowedToCreateRoles() {
        var usersThatCanCreateRoles = new HashSet<UserDto>();
        usersThatCanCreateRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCanCreateRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles_ = usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles();
        roles_.addAll(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles());
        usersThatCanCreateRoles.add(DtosHelper.createRandomUserDto(roles_));
        createTestUsers(usersThatCanCreateRoles);
        for (var creator : usersThatCanCreateRoles) {
            var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
            var roles = DtosHelper.createRandomRoleDtos(2);
            TEST_ROLES.addAll(roles);
            LOGGER.info("Using user: '{}' to create roles:\n{}", creator.getUsername(), ToJsonForLoggingUtil.toJson(roles));
            var response = AdminUserCallsHelper.createRoles(accessToken, roles);
            LOGGER.info("Validating response to create roles:\n{}", response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfRolesCreation(response, creator, roles, "");
        }
    }

    @Test
    public void test_CreateRoles_UsingUsersWithRolesNotAllowedToCreateRoles() {
        var usersThatCannotCreateRoles = new HashSet<UserDto>();
        usersThatCannotCreateRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCannotCreateRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotCreateRoles);
        var roles = DtosHelper.createRandomRoleDtos(2);
        for (var creator : usersThatCannotCreateRoles) {
            var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
            LOGGER.info("Attempting to create roles:\n{} using user: '{}'", ToJsonForLoggingUtil.toJson(roles), creator.getUsername());
            var response = AdminUserCallsHelper.createRoles(accessToken, roles);
            LOGGER.info("Validating response for attempt to create roles:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_CreateRoles_InvalidInputs() {
        var creator = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(creator.getUsername(), creator.getPassword());
        var testRole1 = new RoleDto();
        var testRole2 = DtosHelper.createRandomRoleDto();
        LOGGER.info("Attempting to create roles with with any or all null role names:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testRole1, testRole2)));
        var response = AdminUserCallsHelper.createRoles(accessToken, Set.of(testRole1, testRole2));
        LOGGER.info("Validating response for attempt to create roles with with any or all null role names:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("invalid_inputs", not(empty()));
        for (var entry : InvalidInputsHelper.invalidRoleNames()) {
            testRole1.setRoleName(entry);
            LOGGER.info("Attempting to create roles with invalid role name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testRole1, testRole2)));
            response = AdminUserCallsHelper.createRoles(accessToken, Set.of(testRole1, testRole2));
            LOGGER.info("Validating response for attempt to create roles with invalid role name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("invalid_inputs", not(empty()));
        }
        testRole1.setRoleName(testRole2.getRoleName());
        LOGGER.info("Attempting to create roles with duplicate role names: '{}'\n{}", testRole1.getRoleName(), ToJsonForLoggingUtil.toJson(Set.of(testRole1, testRole2)));
        response = AdminUserCallsHelper.createRoles(accessToken, Set.of(testRole1, testRole2));
        LOGGER.info("Validating response for attempt to create roles with duplicate role names: '{}'\n{}", testRole1.getRoleName(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("duplicate_role_names", not(empty()));
        var existingRole = createTestRole();
        testRole1.setRoleName(existingRole.getRoleName());
        LOGGER.info("Attempting to create roles with existing role name: '{}'\n{}", existingRole.getRoleName(), ToJsonForLoggingUtil.toJson(Set.of(testRole1, testRole2)));
        response = AdminUserCallsHelper.createRoles(accessToken, Set.of(testRole1, testRole2));
        LOGGER.info("Validating response for attempt to create roles with existing role name: '{}'\n{}", existingRole.getRoleName(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("already_existing_roles", not(empty()));
        testRole1 = DtosHelper.createRandomRoleDto();
        testRole1.setPermissions(Set.of(Permissions.CAN_CREATE_USER.name(), "NON_EXISTING_PERMISSION_" + creator.getUsername()));
        LOGGER.info("Attempting to create roles with some or all non-existing permissions: '{}'\n{}", ToJsonForLoggingUtil.toJson(testRole1.getPermissions()), ToJsonForLoggingUtil.toJson(Set.of(testRole1, testRole2)));
        response = AdminUserCallsHelper.createRoles(accessToken, Set.of(testRole1, testRole2));
        LOGGER.info("Validating response for attempt to create roles with some or all non-existing permissions:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("non_existing_permissions", not(empty()));
    }

    @Test
    public void test_DeleteRole_UsingUsersWhoAreAllowedToDeleteRoles() {
        var usersThatCanDeleteRole = new HashSet<UserDto>();
        usersThatCanDeleteRole.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCanDeleteRole.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles_ = usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles();
        roles_.addAll(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles());
        usersThatCanDeleteRole.add(DtosHelper.createRandomUserDto(roles_));
        createTestUsers(usersThatCanDeleteRole);
        var roles = createTestRoles(usersThatCanDeleteRole.size());
        var iterator = roles.iterator();
        for (var deleter : usersThatCanDeleteRole) {
            var roleToBeDeleted = iterator.next();
            var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
            LOGGER.info("Using user: '{}' to delete role: '{}'", deleter.getUsername(), roleToBeDeleted.getRoleName());
            var response = AdminUserCallsHelper.deleteRole(accessToken, roleToBeDeleted.getRoleName());
            LOGGER.info("Validating response to delete role: '{}'\n{}", roleToBeDeleted.getRoleName(), response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", equalTo("Role deleted successfully"));
        }
    }

    @Test
    public void test_DeleteRole_UsingUsersWhoAreNotAllowedToDeleteRoles() {
        var usersThatCannotDeleteRole = new HashSet<UserDto>();
        usersThatCannotDeleteRole.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCannotDeleteRole.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotDeleteRole);
        var testRole = DtosHelper.createRandomRoleDto();
        for (var deleter : usersThatCannotDeleteRole) {
            var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
            LOGGER.info("Attempting to delete role: '{}' using user: '{}'", testRole.getRoleName(), deleter.getUsername());
            var response = AdminUserCallsHelper.deleteRole(accessToken, testRole.getRoleName());
            LOGGER.info("Validating response for attempt to delete role:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_DeleteRole_InvalidInputs() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        for (var entry : InvalidInputsHelper.invalidRoleNames()) {
            LOGGER.info("Attempting to delete role with role name: '{}'", entry);
            var response = AdminUserCallsHelper.deleteRole(accessToken, entry);
            LOGGER.info("Validating response for attempt to delete role with role name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Role: '" + entry + "' not found"));
        }
        LOGGER.info("Attempting to delete role with non-existing role name: 'R_{}'", deleter.getUsername());
        var response = AdminUserCallsHelper.deleteRole(accessToken, "R_" + deleter.getUsername());
        LOGGER.info("Validating response for attempt to delete role with non-existing role name: 'R_{}'\n{}", deleter.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Role: 'R_" + deleter.getUsername() + "' not found"));
        LOGGER.info("Attempting to delete system role: '{}'", Roles.ROLE_SUPER_ADMIN.name());
        response = AdminUserCallsHelper.deleteRole(accessToken, Roles.ROLE_SUPER_ADMIN.name());
        LOGGER.info("Validating response for attempt to delete system role: '{}'\n{}", Roles.ROLE_SUPER_ADMIN.name(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("You cannot delete system role"));
        var existingRole = createTestRole();
        createTestUser(Set.of(existingRole.getRoleName()));
        LOGGER.info("Attempting to delete role which is assigned to some user: '{}'", existingRole.getRoleName());
        response = AdminUserCallsHelper.deleteRole(accessToken, existingRole.getRoleName());
        LOGGER.info("Validating response for attempt to delete role which is assigned to some user: '{}'\n{}", existingRole.getRoleName(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("You cannot delete roles that are assigned to users"));
    }

    @Test
    public void test_DeleteRoles_UsingUsersWhoAreAllowedToDeleteRoles() {
        var usersThatCanDeleteRoles = new HashSet<UserDto>();
        usersThatCanDeleteRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCanDeleteRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles_ = usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles();
        roles_.addAll(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles());
        usersThatCanDeleteRoles.add(DtosHelper.createRandomUserDto(roles_));
        createTestUsers(usersThatCanDeleteRoles);
        var roles = createTestRoles(usersThatCanDeleteRoles.size() * 2);
        var iterator = roles.iterator();
        for (var deleter : usersThatCanDeleteRoles) {
            var rolesToBeDeleted = Set.of(iterator.next().getRoleName(), iterator.next().getRoleName());
            var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
            LOGGER.info("Using user: '{}' to delete roles: '{}'", deleter.getUsername(), ToJsonForLoggingUtil.toJson(rolesToBeDeleted));
            var response = AdminUserCallsHelper.deleteRoles(accessToken, rolesToBeDeleted);
            LOGGER.info("Validating response to delete roles:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200).body("message", equalTo("Roles deleted successfully"));
        }
    }

    @Test
    public void test_DeleteRoles_UsingUsersWhoAreNotAllowedToDeleteRoles() {
        var usersThatCannotDeleteRoles = new HashSet<UserDto>();
        usersThatCannotDeleteRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCannotDeleteRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotDeleteRoles);
        var rolesDto = DtosHelper.createRandomRoleDtos(2);
        var roles = rolesDto.stream().map(RoleDto::getRoleName).collect(Collectors.toSet());
        for (var deleter : usersThatCannotDeleteRoles) {
            var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
            LOGGER.info("Attempting to delete roles: '{}' using user: '{}'", ToJsonForLoggingUtil.toJson(roles), deleter.getUsername());
            var response = AdminUserCallsHelper.deleteRoles(accessToken, roles);
            LOGGER.info("Validating response for attempt to delete roles:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_DeleteRoles_InvalidInputs() {
        var deleter = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(deleter.getUsername(), deleter.getPassword());
        var oneOrMoreNullRoleNames = new HashSet<String>();
        oneOrMoreNullRoleNames.add(null);
        oneOrMoreNullRoleNames.add("R_" + deleter.getUsername());
        LOGGER.info("Attempting to delete roles with one or more null role names: '{}'", oneOrMoreNullRoleNames);
        var response = AdminUserCallsHelper.deleteRoles(accessToken, oneOrMoreNullRoleNames);
        LOGGER.info("Validating response for attempt to delete roles with one or more null role names: '{}'\n{}", oneOrMoreNullRoleNames, response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_roles", not(empty()));
        for (var entry : InvalidInputsHelper.invalidRoleNames()) {
            LOGGER.info("Attempting to delete roles with one or more invalid role names: '{}'", entry);
            response = AdminUserCallsHelper.deleteRoles(accessToken, Set.of(entry));
            LOGGER.info("Validating response for attempt to delete roles with one or more invalid role names: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("not_found_roles", not(empty()));
        }
        LOGGER.info("Attempting to delete roles with role names: '{}'", InvalidInputsHelper.invalidRoleNames());
        response = AdminUserCallsHelper.deleteRoles(accessToken, InvalidInputsHelper.invalidRoleNames());
        LOGGER.info("Validating response for attempt to delete roles with role names: '{}'\n{}", InvalidInputsHelper.invalidRoleNames(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_roles", not(empty()));
        LOGGER.info("Attempting to delete roles with one or more non-existing role names: '{}'", Set.of("R_" + deleter.getUsername()));
        response = AdminUserCallsHelper.deleteRoles(accessToken, Set.of("R_" + deleter.getUsername()));
        LOGGER.info("Validating response for attempt to delete roles with one or more non-existing role names: '{}'\n{}", Set.of("R_" + deleter.getUsername()), response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_roles", not(empty()));
        LOGGER.info("Attempting to delete roles with one or more system roles present: '{}'", Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        response = AdminUserCallsHelper.deleteRoles(accessToken, Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        LOGGER.info("Validating response for attempt to delete roles with one or more system roles present: '{}'\n{}", Set.of(Roles.ROLE_SUPER_ADMIN.name()), response.getBody().asPrettyString());
        response.then().statusCode(400).body("cannot_delete_system_roles", not(empty()));
        var existingRole = createTestRole();
        createTestUser(Set.of(existingRole.getRoleName()));
        LOGGER.info("Attempting to delete roles with one or more roles assigned to some users: '{}'", Set.of(existingRole.getRoleName()));
        response = AdminUserCallsHelper.deleteRoles(accessToken, Set.of(existingRole.getRoleName()));
        LOGGER.info("Validating response for attempt to delete roles with one or more roles assigned to some users: '{}'\n{}", Set.of(existingRole.getRoleName()), response.getBody().asPrettyString());
        response.then().statusCode(400).body("cannot_delete_roles_assigned_to_users", not(empty()));
    }

    @Test
    public void test_GetRole_UsingUsersWithRolesAllowedToReadRoles() {
        var usersThatCanReadRoles = new HashSet<UserDto>();
        usersThatCanReadRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCanReadRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles();
        roles.addAll(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles());
        usersThatCanReadRoles.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCanReadRoles);
        var existingRoleName = Roles.ROLE_ADMIN.name();
        for (var user : usersThatCanReadRoles) {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Using user: '{}' to get role: '{}'", user.getUsername(), existingRoleName);
            var response = AdminUserCallsHelper.getRole(accessToken, existingRoleName);
            LOGGER.info("Validating response to get role:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200).body("roleName", equalTo(existingRoleName));
        }
    }

    @Test
    public void test_GetRole_UsingUsersWithRolesNotAllowedToReadRoles() {
        var usersThatCannotReadRoles = new HashSet<UserDto>();
        usersThatCannotReadRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCannotReadRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotReadRoles);
        for (var user : usersThatCannotReadRoles) {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Attempting to get role: '{}' using user: '{}'", Roles.ROLE_ADMIN.name(), user.getUsername());
            var response = AdminUserCallsHelper.getRole(accessToken, Roles.ROLE_ADMIN.name());
            LOGGER.info("Validating response for attempt to get role:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_GetRole_InvalidInputs() {
        var user = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        for (var entry : InvalidInputsHelper.invalidRoleNames()) {
            LOGGER.info("Attempting to get role with invalid role name: '{}'", entry);
            var response = AdminUserCallsHelper.getRole(accessToken, entry);
            LOGGER.info("Validating response for attempt to get role with invalid role name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Role: '" + entry + "' not found"));
        }
        LOGGER.info("Attempting to get role with non-existing role name: 'R_{}'", user.getUsername());
        var response = AdminUserCallsHelper.getRole(accessToken, "R_" + user.getUsername());
        LOGGER.info("Validating response for attempt to get role with non-existing role name: 'R_{}'\n{}", user.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Role: 'R_" + user.getUsername() + "' not found"));
    }

    @Test
    public void test_GetRoles_UsingUsersWithRolesAllowedToReadRoles() {
        var usersThatCanReadRoles = new HashSet<UserDto>();
        usersThatCanReadRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCanReadRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles();
        roles.addAll(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles());
        usersThatCanReadRoles.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCanReadRoles);
        var existingRoleNames = Set.of(Roles.ROLE_ADMIN.name(), Roles.ROLE_MANAGE_ROLES.name());
        for (var user : usersThatCanReadRoles) {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Using user: '{}' to get roles: '{}'", user.getUsername(), ToJsonForLoggingUtil.toJson(existingRoleNames));
            var response = AdminUserCallsHelper.getRoles(accessToken, existingRoleNames);
            LOGGER.info("Validating response to get roles:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200).body("size()", equalTo(existingRoleNames.size()));
        }
    }

    @Test
    public void test_GetRoles_UsingUsersWithRolesNotAllowedToReadRoles() {
        var usersThatCannotReadRoles = new HashSet<UserDto>();
        usersThatCannotReadRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCannotReadRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotReadRoles);
        for (var user : usersThatCannotReadRoles) {
            var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
            LOGGER.info("Attempting to get roles: '{}' using user: '{}'", Set.of(Roles.ROLE_ADMIN.name(), Roles.ROLE_MANAGE_ROLES.name()), user.getUsername());
            var response = AdminUserCallsHelper.getRoles(accessToken, Set.of(Roles.ROLE_ADMIN.name(), Roles.ROLE_MANAGE_ROLES.name()));
            LOGGER.info("Validating response for attempt to get roles:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_GetRoles_InvalidInputs() {
        var user = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(user.getUsername(), user.getPassword());
        var oneOrMoreNullRoleNames = new HashSet<String>();
        oneOrMoreNullRoleNames.add(null);
        oneOrMoreNullRoleNames.add("AutoTestRole_" + user.getUsername());
        LOGGER.info("Attempting to get roles with one or more null role names: '{}'", oneOrMoreNullRoleNames);
        var response = AdminUserCallsHelper.getRoles(accessToken, oneOrMoreNullRoleNames);
        LOGGER.info("Validating response for attempt to get roles with one or more null role names: '{}'\n{}", oneOrMoreNullRoleNames, response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_roles", not(empty()));
        LOGGER.info("Attempting to get roles with role names: '{}'", InvalidInputsHelper.invalidRoleNames());
        response = AdminUserCallsHelper.getRoles(accessToken, InvalidInputsHelper.invalidRoleNames());
        LOGGER.info("Validating response for attempt to get roles with role names: '{}'\n{}", InvalidInputsHelper.invalidRoleNames(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_roles", not(empty()));
        LOGGER.info("Attempting to get roles with one or more non-existing role names: '{}'", Set.of("R_" + user.getUsername()));
        response = AdminUserCallsHelper.getRoles(accessToken, Set.of("R_" + user.getUsername()));
        LOGGER.info("Validating response for attempt to get roles with one or more non-existing role names: '{}'\n{}", Set.of("R_" + user.getUsername()), response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_roles", not(empty()));
    }

    @Test
    public void test_UpdateRole_UsingUsersWithRolesAllowedToUpdateRoles() {
        var usersThatCanUpdateRole = new HashSet<UserDto>();
        usersThatCanUpdateRole.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCanUpdateRole.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles();
        roles.addAll(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles());
        usersThatCanUpdateRole.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCanUpdateRole);
        var existingRoles = createTestRoles(usersThatCanUpdateRole.size());
        var iterator = existingRoles.iterator();
        for (var updater : usersThatCanUpdateRole) {
            var roleToBeUpdated = iterator.next();
            var updatedInput = new RoleDto();
            updatedInput.setRoleName(roleToBeUpdated.getRoleName());
            updatedInput.setPermissions(Set.of(Permissions.CAN_CREATE_USER.name(), Permissions.CAN_READ_USER.name()));
            var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
            LOGGER.info("Using user: '{}' to update role: '{}'", updater.getUsername(), ToJsonForLoggingUtil.toJson(updatedInput));
            var response = AdminUserCallsHelper.updateRole(accessToken, updatedInput);
            LOGGER.info("Validating response to update role:\n{}", response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfRoleUpdate(response, updater, roleToBeUpdated, updatedInput);
            roleToBeUpdated.setRoleName(updatedInput.getRoleName());
        }
    }

    @Test
    public void test_UpdateRole_UsingUsersWithRolesNotAllowedToUpdateRoles() {
        var usersThatCannotUpdateRole = new HashSet<UserDto>();
        usersThatCannotUpdateRole.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCannotUpdateRole.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotUpdateRole);
        var testRole = DtosHelper.createRandomRoleDto();
        for (var updater : usersThatCannotUpdateRole) {
            var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
            LOGGER.info("Attempting to update role: '{}' using user: '{}'", testRole.getRoleName(), updater.getUsername());
            var response = AdminUserCallsHelper.updateRole(accessToken, testRole);
            LOGGER.info("Validating response for attempt to update role:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_UpdateRole_InvalidInputs() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        var testRole = new RoleDto();
        LOGGER.info("Attempting to update role with null role name:\n{}", ToJsonForLoggingUtil.toJson(testRole));
        var response = AdminUserCallsHelper.updateRole(accessToken, testRole);
        LOGGER.info("Validating response for attempt to update role with null role name:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Role: '" + testRole.getRoleName() + "' not found"));
        for (var entry : InvalidInputsHelper.invalidRoleNames()) {
            testRole.setRoleName(entry);
            LOGGER.info("Attempting to update role with invalid role name: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(testRole));
            response = AdminUserCallsHelper.updateRole(accessToken, testRole);
            LOGGER.info("Validating response for attempt to update role with invalid role name: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("Role: '" + entry + "' not found"));
        }
        testRole.setRoleName("R_" + updater.getUsername());
        LOGGER.info("Attempting to update a non-existing role: '{}'\n{}", testRole.getRoleName(), ToJsonForLoggingUtil.toJson(testRole));
        response = AdminUserCallsHelper.updateRole(accessToken, testRole);
        LOGGER.info("Validating response for attempt to update a non-existing role: '{}'\n{}", testRole.getRoleName(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Role: '" + testRole.getRoleName() + "' not found"));
        testRole.setRoleName(Roles.ROLE_SUPER_ADMIN.name());
        LOGGER.info("Attempting to update system role: '{}'\n{}", Roles.ROLE_SUPER_ADMIN.name(), ToJsonForLoggingUtil.toJson(testRole));
        response = AdminUserCallsHelper.updateRole(accessToken, testRole);
        LOGGER.info("Validating response for attempt to update system role: '{}'\n{}", Roles.ROLE_SUPER_ADMIN.name(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Cannot modify system role: '" + Roles.ROLE_SUPER_ADMIN.name() + "'"));
        var existingRole = createTestRole();
        existingRole.setPermissions(Set.of(Permissions.CAN_CREATE_USER.name(), "P_" + updater.getUsername()));
        LOGGER.info("Attempting to update role with some or all non-existing permissions: '{}'\n{}", ToJsonForLoggingUtil.toJson(existingRole.getPermissions()), ToJsonForLoggingUtil.toJson(existingRole));
        response = AdminUserCallsHelper.updateRole(accessToken, existingRole);
        LOGGER.info("Validating response for attempt to update role with some or all non-existing permissions:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("non_existing_permissions", not(empty()));
    }

    @Test
    public void test_UpdateRoles_UsingUsersWithRolesAllowedToUpdateRoles() {
        var usersThatCanUpdateRoles = new HashSet<UserDto>();
        usersThatCanUpdateRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCanUpdateRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles();
        roles.addAll(usersWithTheseRoles_AllowedTo_CreateReadUpdateDelete_Roles());
        usersThatCanUpdateRoles.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCanUpdateRoles);
        var existingRoles = createTestRoles(usersThatCanUpdateRoles.size() * 2);
        var iterator = existingRoles.iterator();
        for (var updater : usersThatCanUpdateRoles) {
            var rolesToBeUpdated = Set.of(iterator.next(), iterator.next());
            var updatedInputs = new HashSet<RoleDto>();
            rolesToBeUpdated.forEach(role -> {
                var updatedInput = new RoleDto();
                updatedInput.setRoleName(role.getRoleName());
                updatedInput.setPermissions(Set.of(Permissions.CAN_CREATE_USER.name(), Permissions.CAN_READ_USER.name()));
                updatedInputs.add(updatedInput);
            });
            var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
            LOGGER.info("Using user: '{}' to update roles:\n{}", updater.getUsername(), ToJsonForLoggingUtil.toJson(updatedInputs));
            var response = AdminUserCallsHelper.updateRoles(accessToken, updatedInputs);
            LOGGER.info("Validating response to update roles:\n{}", response.getBody().asPrettyString());
            ResponseValidatorHelper.validateResponseOfRolesUpdate(response, updater, rolesToBeUpdated, updatedInputs,"");
        }
    }

    @Test
    public void test_UpdateRoles_UsingUsersWithRolesNotAllowedToUpdateRoles() {
        var usersThatCannotUpdateRoles = new HashSet<UserDto>();
        usersThatCannotUpdateRoles.add(DtosHelper.createRandomUserDto(usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()));
        for (var role : usersWithTheseRoles_NotAllowedTo_CreateReadUpdateDelete_Roles()) {
            usersThatCannotUpdateRoles.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCannotUpdateRoles);
        var rolesDto = DtosHelper.createRandomRoleDtos(2);
        var roles = rolesDto.stream().map(RoleDto::getRoleName).collect(Collectors.toSet());
        for (var updater : usersThatCannotUpdateRoles) {
            var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
            LOGGER.info("Attempting to update roles: '{}' using user: '{}'", ToJsonForLoggingUtil.toJson(roles), updater.getUsername());
            var response = AdminUserCallsHelper.updateRoles(accessToken, rolesDto);
            LOGGER.info("Validating response for attempt to update roles:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_UpdateRoles_InvalidInputs() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        var testRole1 = new RoleDto();
        var testRole2 = DtosHelper.createRandomRoleDto();
        LOGGER.info("Attempting to update roles with one or more null role names:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testRole1, testRole2)));
        var response = AdminUserCallsHelper.updateRoles(accessToken, Set.of(testRole1, testRole2));
        LOGGER.info("Validating response for attempt to update roles with one or more null role names:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_rolenames", not(empty()));
        for (var entry : InvalidInputsHelper.invalidRoleNames()) {
            testRole1.setRoleName(entry);
            LOGGER.info("Attempting to update roles with one or more invalid role names: '{}'\n{}", entry, ToJsonForLoggingUtil.toJson(Set.of(testRole1, testRole2)));
            response = AdminUserCallsHelper.updateRoles(accessToken, Set.of(testRole1, testRole2));
            LOGGER.info("Validating response for attempt to update roles with one or more invalid role names: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("not_found_rolenames", not(empty()));
        }
        testRole1.setRoleName(testRole2.getRoleName());
        LOGGER.info("Attempting to update roles with duplicate role names:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testRole1, testRole2)));
        response = AdminUserCallsHelper.updateRoles(accessToken, Set.of(testRole1, testRole2));
        LOGGER.info("Validating response for attempt to update roles with duplicate role names:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("duplicate_role_names", not(empty()));
        testRole1.setRoleName("R_" + updater.getUsername());
        LOGGER.info("Attempting to update roles with one or more non-existing role names:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testRole1)));
        response = AdminUserCallsHelper.updateRoles(accessToken, Set.of(testRole1));
        LOGGER.info("Validating response for attempt to update roles with one or more non-existing role names:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("not_found_roles", not(empty()));
        testRole1.setRoleName(Roles.ROLE_SUPER_ADMIN.name());
        LOGGER.info("Attempting to update roles with one or more system roles present:\n{}", ToJsonForLoggingUtil.toJson(Set.of(testRole1)));
        response = AdminUserCallsHelper.updateRoles(accessToken, Set.of(testRole1));
        LOGGER.info("Validating response for attempt to update roles with one or more system roles present:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("cannot_modify_system_roles", not(empty()));
        var existingRole = createTestRole();
        existingRole.setPermissions(Set.of(Permissions.CAN_CREATE_USER.name(), "P_" + updater.getUsername()));
        LOGGER.info("Attempting to update roles with one or more roles having some or all non-existing permissions:\n{}", ToJsonForLoggingUtil.toJson(Set.of(existingRole)));
        response = AdminUserCallsHelper.updateRoles(accessToken, Set.of(existingRole));
        LOGGER.info("Validating response for attempt to update roles with one or more roles having some or all non-existing permissions:\n{}", response.getBody().asPrettyString());
        response.then().statusCode(400).body("non_existing_permissions", not(empty()));
    }

    @Test
    public void test_EnableEmailMfaForUser_UsingSuperAdminUser() {
        var superAdminUser = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCanBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(superAdminUser.getUsername(), superAdminUser.getPassword());
        var i = 0;
        for (var userToBeUpdated : usersThatCanBeUpdatedBySuperAdmin) {
            LOGGER.info("Using super admin user: '{}' to enable email MFA for user: '{}'", superAdminUser.getUsername(), i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            LOGGER.info("Validating response to enable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", equalTo("Email MFA enabled successfully"))
                    .body("user.username", equalTo(userToBeUpdated.getUsername()))
                    .body("user.email", equalTo(userToBeUpdated.getEmail()))
                    .body("user.mfaMethods", contains(MfaMethods.EMAIL.name()));
            i++;
        }
    }

    @Test
    public void test_EnableEmailMfaForUser_UsingAdminUser() {
        var adminUser = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCanBeUpdatedByAdmin = new HashSet<UserDto>();
        usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(adminUser.getUsername(), adminUser.getPassword());
        var i = 0;
        for (var userToBeUpdated : usersThatCanBeUpdatedByAdmin) {
            LOGGER.info("Using admin user: '{}' to enable email MFA for user: '{}'", adminUser.getUsername(), i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            LOGGER.info("Validating response to enable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", equalTo("Email MFA enabled successfully"))
                    .body("user.username", equalTo(userToBeUpdated.getUsername()))
                    .body("user.email", equalTo(userToBeUpdated.getEmail()))
                    .body("user.mfaMethods", contains(MfaMethods.EMAIL.name()));
            i++;
        }
    }

    @Test
    public void test_EnableEmailMfaForUser_UsingUserWithRoleManageUsers() {
        var manageUsersUser = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCanBeUpdatedByManageUsers = new HashSet<UserDto>();
        usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(manageUsersUser.getUsername(), manageUsersUser.getPassword());
        var i = 0;
        for (var userToBeUpdated : usersThatCanBeUpdatedByManageUsers) {
            LOGGER.info("Using user with role 'Manage Users': '{}' to enable email MFA for user: '{}'", manageUsersUser.getUsername(), i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            LOGGER.info("Validating response to enable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", equalTo("Email MFA enabled successfully"))
                    .body("user.username", equalTo(userToBeUpdated.getUsername()))
                    .body("user.email", equalTo(userToBeUpdated.getEmail()))
                    .body("user.mfaMethods", contains(MfaMethods.EMAIL.name()));
            i++;
        }
    }

    @Test
    public void test_EnableEmailMfaForUser_UsingUsersWhoAreNotAllowedToUpdate() {
        var updaters = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            updaters.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(updaters);
        var testUser = DtosHelper.createRandomUserDto();
        for (var updater : updaters) {
            var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
            LOGGER.info("Attempting to enable email MFA for user: '{}' using: '{}'", testUser.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, testUser.getUsername());
            LOGGER.info("Validating response for attempt to enable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_EnableEmailMfaForUser_InvalidInputs() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to enable email MFA for user with invalid username: '{}'", entry);
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, entry);
            LOGGER.info("Validating response for attempt to enable email MFA for user with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to enable email MFA for user with invalid email: '{}'", entry);
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, entry);
            LOGGER.info("Validating response for attempt to enable email MFA for user with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        LOGGER.info("Attempting to enable email MFA for user with non-existing username: 'U_{}'", updater.getUsername());
        var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, "U_" + updater.getUsername());
        LOGGER.info("Validating response for attempt to enable email MFA for user with non-existing username: 'U_{}'\n{}", updater.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found"));
        LOGGER.info("Attempting to enable email MFA for user with non-existing email: 'E_{}'", updater.getEmail());
        response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, "E_" + updater.getEmail());
        LOGGER.info("Validating response for attempt to enable email MFA for user with non-existing email: 'E_{}'\n{}", updater.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found"));
        LOGGER.info("Attempting to enable email MFA of our own account: '{}'", updater.getUsername());
        response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, updater.getUsername());
        LOGGER.info("Validating response for attempt to enable email MFA of our own account: '{}'\n{}", updater.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString(updater.getUsername() + "(You cannot modify your own account using this endpoint)"));
        LOGGER.info("Attempting to enable email MFA of our own account: '{}'", updater.getEmail());
        response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, updater.getEmail());
        LOGGER.info("Validating response for attempt to enable email MFA of our own account: '{}'\n{}", updater.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString(updater.getEmail() + "(You cannot modify your own account using this endpoint)"));
        var testUser = createTestUser();
        LOGGER.info("Enabling email MFA for user: '{}'", testUser.getUsername());
        CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(testUser.getUsername()).then().statusCode(200);
        LOGGER.info("Attempting to enable email MFA for user who already has email MFA enabled: '{}'", testUser.getUsername());
        response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, testUser.getUsername());
        LOGGER.info("Validating response for attempt to enable email MFA for user who already has email MFA enabled: '{}'\n{}", testUser.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email MFA is already enabled for user: '" + testUser.getUsername() + "'"));
    }

    @Test
    public void test_EnableEmailMfaForUser_UsingUserWithRoleSuperAdmin_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCannotBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedBySuperAdmin) {
            LOGGER.info("Attempting to enable email MFA for user: '{}' using user with role 'Super Admin': '{}'", userToBeUpdated.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, userToBeUpdated.getUsername());
            LOGGER.info("Validating response for attempt to enable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_EnableEmailMfaForUser_UsingUserWithRoleAdmin_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCannotBeUpdatedByAdmin = new HashSet<UserDto>();
        usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedByAdmin) {
            LOGGER.info("Attempting to enable email MFA for user: '{}' using user with role 'Admin': '{}'", userToBeUpdated.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, userToBeUpdated.getUsername());
            LOGGER.info("Validating response for attempt to enable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_EnableEmailMfaForUser_UsingUserWithRoleManageUsers_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCannotBeUpdatedByManageUsers = new HashSet<UserDto>();
        usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedByManageUsers) {
            LOGGER.info("Attempting to enable email MFA for user: '{}' using user with role 'Manage Users': '{}'", userToBeUpdated.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.enableEmailMfaForUser(accessToken, userToBeUpdated.getUsername());
            LOGGER.info("Validating response for attempt to enable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DisableEmailMfaForUser_UsingSuperAdminUser() {
        var superAdminUser = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCanBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(superAdminUser.getUsername(), superAdminUser.getPassword());
        var i = 0;
        for (var userToBeUpdated : usersThatCanBeUpdatedBySuperAdmin) {
            CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(userToBeUpdated.getUsername()).then().statusCode(200);
            LOGGER.info("Using super admin user: '{}' to disable email MFA for user: '{}'", superAdminUser.getUsername(), i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            LOGGER.info("Validating response to disable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", equalTo("Email MFA disabled successfully"))
                    .body("user.username", equalTo(userToBeUpdated.getUsername()))
                    .body("user.email", equalTo(userToBeUpdated.getEmail()))
                    .body("user.mfaMethods", not(contains(MfaMethods.EMAIL.name())));
            i++;
        }
    }

    @Test
    public void test_DisableEmailMfaForUser_UsingAdminUser() {
        var adminUser = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCanBeUpdatedByAdmin = new HashSet<UserDto>();
        usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(adminUser.getUsername(), adminUser.getPassword());
        var i = 0;
        for (var userToBeUpdated : usersThatCanBeUpdatedByAdmin) {
            CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(userToBeUpdated.getUsername()).then().statusCode(200);
            LOGGER.info("Using admin user: '{}' to disable email MFA for user: '{}'", adminUser.getUsername(), i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            LOGGER.info("Validating response to disable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", equalTo("Email MFA disabled successfully"))
                    .body("user.username", equalTo(userToBeUpdated.getUsername()))
                    .body("user.email", equalTo(userToBeUpdated.getEmail()))
                    .body("user.mfaMethods", not(contains(MfaMethods.EMAIL.name())));
            i++;
        }
    }

    @Test
    public void test_DisableEmailMfaForUser_UsingUserWithRoleManageUsers() {
        var manageUsersUser = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCanBeUpdatedByManageUsers = new HashSet<UserDto>();
        usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto());
        usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_CreateUpdateDelete_Users()) {
            usersThatCanBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(usersThatCanBeUpdatedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(manageUsersUser.getUsername(), manageUsersUser.getPassword());
        var i = 0;
        for (var userToBeUpdated : usersThatCanBeUpdatedByManageUsers) {
            CallsUsingGlobalAdminUserHelper.enableEmailMfaForUser(userToBeUpdated.getUsername()).then().statusCode(200);
            LOGGER.info("Using user with role 'Manage Users': '{}' to disable email MFA for user: '{}'", manageUsersUser.getUsername(), i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, i % 2 == 0 ? userToBeUpdated.getUsername() : userToBeUpdated.getEmail());
            LOGGER.info("Validating response to disable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(200)
                    .body("message", equalTo("Email MFA disabled successfully"))
                    .body("user.username", equalTo(userToBeUpdated.getUsername()))
                    .body("user.email", equalTo(userToBeUpdated.getEmail()))
                    .body("user.mfaMethods", not(contains(MfaMethods.EMAIL.name())));
            i++;
        }
    }

    @Test
    public void test_DisableEmailMfaForUser_UsingUsersWhoAreNotAllowedToUpdate() {
        var updaters = new HashSet<UserDto>();
        for (var role : usersWithTheseRolesAreNotAllowedTo_CreateUpdateDeleteRead_Users()) {
            updaters.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        createTestUsers(updaters);
        var testUser = DtosHelper.createRandomUserDto();
        for (var updater : updaters) {
            var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
            LOGGER.info("Attempting to disable email MFA for user: '{}' using: '{}'", testUser.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, testUser.getUsername());
            LOGGER.info("Validating response for attempt to disable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(403).body("message", containsString("Access Denied"));
        }
    }

    @Test
    public void test_DisableEmailMfaForUser_InvalidInputs() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var entry : InvalidInputsHelper.invalidUsernames()) {
            LOGGER.info("Attempting to disable email MFA for user with invalid username: '{}'", entry);
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, entry);
            LOGGER.info("Validating response for attempt to disable email MFA for user with invalid username: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        for (var entry : InvalidInputsHelper.invalidEmails()) {
            LOGGER.info("Attempting to disable email MFA for user with invalid email: '{}'", entry);
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, entry);
            LOGGER.info("Validating response for attempt to disable email MFA for user with invalid email: '{}'\n{}", entry, response.getBody().asPrettyString());
            response.then().statusCode(400).body("message", containsString("User not found"));
        }
        LOGGER.info("Attempting to disable email MFA for user with non-existing username: 'U_{}'", updater.getUsername());
        var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, "U_" + updater.getUsername());
        LOGGER.info("Validating response for attempt to disable email MFA for user with non-existing username: 'U_{}'\n{}", updater.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found"));
        LOGGER.info("Attempting to disable email MFA for user with non-existing email: 'E_{}'", updater.getEmail());
        response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, "E_" + updater.getEmail());
        LOGGER.info("Validating response for attempt to disable email MFA for user with non-existing email: 'E_{}'\n{}", updater.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("User not found"));
        LOGGER.info("Attempting to disable email MFA of our own account: '{}'", updater.getUsername());
        response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, updater.getUsername());
        LOGGER.info("Validating response for attempt to disable email MFA of our own account: '{}'\n{}", updater.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString(updater.getUsername() + "(You cannot modify your own account using this endpoint)"));
        LOGGER.info("Attempting to disable email MFA of our own account: '{}'", updater.getEmail());
        response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, updater.getEmail());
        LOGGER.info("Validating response for attempt to disable email MFA of our own account: '{}'\n{}", updater.getEmail(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString(updater.getEmail() + "(You cannot modify your own account using this endpoint)"));
        var testUser = createTestUser();
        LOGGER.info("Attempting to disable email MFA for user who does not have email MFA enabled: '{}'", testUser.getUsername());
        response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, testUser.getUsername());
        LOGGER.info("Validating response for attempt to disable email MFA for user who does not have email MFA enabled: '{}'\n{}", testUser.getUsername(), response.getBody().asPrettyString());
        response.then().statusCode(400).body("message", containsString("Email MFA is already disabled for user: '" + testUser.getUsername() + "'"));
    }

    @Test
    public void test_DisableEmailMfaForUser_UsingUserWithRoleSuperAdmin_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_SUPER_ADMIN.name()));
        var usersThatCannotBeUpdatedBySuperAdmin = new HashSet<UserDto>();
        usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForSuperAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForSuperAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedBySuperAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedBySuperAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedBySuperAdmin) {
            LOGGER.info("Attempting to disable email MFA for user: '{}' using user with role 'Super Admin': '{}'", userToBeUpdated.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, userToBeUpdated.getUsername());
            LOGGER.info("Validating response for attempt to disable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DisableEmailMfaForUser_UsingUserWithRoleAdmin_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_ADMIN.name()));
        var usersThatCannotBeUpdatedByAdmin = new HashSet<UserDto>();
        usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedByAdmin.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedByAdmin);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedByAdmin) {
            LOGGER.info("Attempting to disable email MFA for user: '{}' using user with role 'Admin': '{}'", userToBeUpdated.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, userToBeUpdated.getUsername());
            LOGGER.info("Validating response for attempt to disable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }

    @Test
    public void test_DisableEmailMfaForUser_UsingUserWithRoleManageUsers_NotAllowedToUpdate() {
        var updater = createTestUser(Set.of(Roles.ROLE_MANAGE_USERS.name()));
        var usersThatCannotBeUpdatedByManageUsers = new HashSet<UserDto>();
        usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()));
        for (var role : rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users()) {
            usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(Set.of(role)));
        }
        var roles = rolesSetForAdmin_CreateUpdateDelete_Users();
        roles.addAll(rolesSetForAdmin_NotAllowedTo_CreateUpdateDelete_Users());
        usersThatCannotBeUpdatedByManageUsers.add(DtosHelper.createRandomUserDto(roles));
        createTestUsers(usersThatCannotBeUpdatedByManageUsers);
        var accessToken = AuthCallsHelper.getAccessToken(updater.getUsername(), updater.getPassword());
        for (var userToBeUpdated : usersThatCannotBeUpdatedByManageUsers) {
            LOGGER.info("Attempting to disable email MFA for user: '{}' using user with role 'Manage Users': '{}'", userToBeUpdated.getUsername(), updater.getUsername());
            var response = AdminUserCallsHelper.disableEmailMfaForUser(accessToken, userToBeUpdated.getUsername());
            LOGGER.info("Validating response for attempt to disable email MFA for user:\n{}", response.getBody().asPrettyString());
            response.then().statusCode(400).body("you_are_not_allowed_to_modify_user_with_these_roles", not(empty()));
        }
    }
}