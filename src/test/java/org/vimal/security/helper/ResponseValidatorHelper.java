package org.vimal.security.helper;

import io.restassured.response.Response;
import org.vimal.security.dto.RoleDto;
import org.vimal.security.dto.UserDto;

import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.*;

public final class ResponseValidatorHelper {
    private ResponseValidatorHelper() {
        throw new AssertionError("Cannot instantiate ResponseValidatorHelper class");
    }

    public static void validateResponseOfUserCreation(Response response,
                                                      UserDto creator,
                                                      UserDto userToBeCreated) {
        response.then().statusCode(200)
                .body("username", equalTo(userToBeCreated.getUsername()))
                .body("email", equalTo(userToBeCreated.getEmail()))
                .body("firstName", equalTo(userToBeCreated.getFirstName()))
                .body("middleName", equalTo(userToBeCreated.getMiddleName()))
                .body("lastName", equalTo(userToBeCreated.getLastName()))
                .body("createdBy", equalTo(creator.getUsername()))
                .body("updatedBy", equalTo(creator.getUsername()))
                .body("roles", (userToBeCreated.getRoles() != null) ?
                        containsInAnyOrder(userToBeCreated.getRoles().toArray()) :
                        empty());
    }

    public static void validateResponseOfUsersCreation(Response response,
                                                       UserDto creator,
                                                       Set<UserDto> usersToBeCreated,
                                                       String pathPrefix) {
        if (!pathPrefix.isBlank()) pathPrefix += ".";
        response.then().statusCode(200)
                .body(pathPrefix + "size()", equalTo(usersToBeCreated.size()));

        for (var user : usersToBeCreated) {
            var findPath = pathPrefix + "find { it.username == '" + user.getUsername() + "' }";
            response.then()
                    .body(findPath + "email", equalTo(user.getEmail()))
                    .body(findPath + "firstName", equalTo(user.getFirstName()))
                    .body(findPath + "middleName", equalTo(user.getMiddleName()))
                    .body(findPath + "lastName", equalTo(user.getLastName()))
                    .body(findPath + "createdBy", equalTo(creator.getUsername()))
                    .body(findPath + "updatedBy", equalTo(creator.getUsername()))
                    .body(findPath + "roles", (user.getRoles() != null) ?
                            containsInAnyOrder(user.getRoles().toArray()) :
                            empty());
        }
    }

    public static void validateResponseOfUserUpdate(Response response,
                                                    UserDto updater,
                                                    UserDto userToBeUpdated,
                                                    UserDto updateInput) {
        response.then().statusCode(200)
                .body("username", updateInput.getUsername() != null ? equalTo(updateInput.getUsername()) : equalTo(userToBeUpdated.getUsername()))
                .body("email", updateInput.getEmail() != null ? equalTo(updateInput.getEmail()) : equalTo(userToBeUpdated.getEmail()))
                .body("firstName", updateInput.getFirstName() != null ? equalTo(updateInput.getFirstName()) : equalTo(userToBeUpdated.getFirstName()))
                .body("middleName", updateInput.getMiddleName() != null ? equalTo(updateInput.getMiddleName()) : equalTo(userToBeUpdated.getMiddleName()))
                .body("lastName", updateInput.getLastName() != null ? equalTo(updateInput.getLastName()) : equalTo(userToBeUpdated.getLastName()))
                .body("updatedBy", equalTo(updater.getUsername()))
                .body("roles", (updateInput.getRoles() != null) ?
                        containsInAnyOrder(updateInput.getRoles().toArray()) :
                        (userToBeUpdated.getRoles() != null) ?
                                containsInAnyOrder(userToBeUpdated.getRoles().toArray()) :
                                empty());
    }

    public static void validateResponseOfUsersUpdate(Response response,
                                                     UserDto updater,
                                                     Set<UserDto> usersToBeUpdated,
                                                     Set<UserDto> updateInputs,
                                                     String pathPrefix) {
        if (!pathPrefix.isBlank()) pathPrefix += ".";
        response.then().statusCode(200)
                .body(pathPrefix + "size()", equalTo(usersToBeUpdated.size()));

        var updateInputMap = updateInputs.stream().collect(Collectors.toMap(UserDto::getUsername, Function.identity()));
        for (var user : usersToBeUpdated) {
            var updateInput = updateInputMap.getOrDefault(user.getUsername(), new UserDto());
            var findPath = pathPrefix + "find { it.username == '" + user.getUsername() + "' }";
            response.then()
                    .body(findPath + "email", updateInput.getEmail() != null ? equalTo(updateInput.getEmail()) : equalTo(user.getEmail()))
                    .body(findPath + "firstName", updateInput.getFirstName() != null ? equalTo(updateInput.getFirstName()) : equalTo(user.getFirstName()))
                    .body(findPath + "middleName", updateInput.getMiddleName() != null ? equalTo(updateInput.getMiddleName()) : equalTo(user.getMiddleName()))
                    .body(findPath + "lastName", updateInput.getLastName() != null ? equalTo(updateInput.getLastName()) : equalTo(user.getLastName()))
                    .body(findPath + "updatedBy", equalTo(updater.getUsername()))
                    .body(findPath + "roles", (updateInput.getRoles() != null) ?
                            containsInAnyOrder(updateInput.getRoles().toArray()) :
                            (user.getRoles() != null) ?
                                    containsInAnyOrder(user.getRoles().toArray()) :
                                    empty());
        }
    }

    public static void validateResponseOfRoleCreation(Response response,
                                                      UserDto creator,
                                                      RoleDto roleToBeCreated) {
        response.then().statusCode(200)
                .body("roleName", equalTo(roleToBeCreated.getRoleName()))
                .body("description", equalTo(roleToBeCreated.getDescription()))
                .body("systemRole", equalTo(false))
                .body("createdBy", equalTo(creator.getUsername()))
                .body("updatedBy", equalTo(creator.getUsername()))
                .body("permissions", (roleToBeCreated.getPermissions() != null) ?
                        containsInAnyOrder(roleToBeCreated.getPermissions().toArray()) :
                        empty());
    }

    public static void validateResponseOfRolesCreation(Response response,
                                                       UserDto creator,
                                                       Set<RoleDto> rolesToBeCreated,
                                                       String pathPrefix) {
        if (!pathPrefix.isBlank()) pathPrefix += ".";
        response.then().statusCode(200)
                .body(pathPrefix + "size()", equalTo(rolesToBeCreated.size()));

        response.then().statusCode(200)
                .body("size()", equalTo(rolesToBeCreated.size()));

        for (var role : rolesToBeCreated) {
            var findPath = pathPrefix + "find { it.roleName == '" + role.getRoleName() + "' }";
            response.then()
                    .body(findPath + "description", equalTo(role.getDescription()))
                    .body(findPath + "systemRole", equalTo(false))
                    .body(findPath + "createdBy", equalTo(creator.getUsername()))
                    .body(findPath + "updatedBy", equalTo(creator.getUsername()))
                    .body(findPath + "permissions", (role.getPermissions() != null) ?
                            containsInAnyOrder(role.getPermissions().toArray()) :
                            empty());
        }
    }

    public static void validateResponseOfRoleUpdate(Response response,
                                                    UserDto updater,
                                                    RoleDto roleToBeUpdated,
                                                    RoleDto updateInput) {
        response.then().statusCode(200)
                .body("roleName", equalTo(roleToBeUpdated.getRoleName()))
                .body("description", updateInput.getDescription() != null && !updateInput.getDescription().isBlank() ? equalTo(updateInput.getDescription()) : equalTo(roleToBeUpdated.getDescription()))
                .body("systemRole", equalTo(false))
                .body("updatedBy", equalTo(updater.getUsername()))
                .body("permissions", (updateInput.getPermissions() != null) ?
                        containsInAnyOrder(updateInput.getPermissions().toArray()) :
                        (roleToBeUpdated.getPermissions() != null) ?
                                containsInAnyOrder(roleToBeUpdated.getPermissions().toArray()) :
                                empty());
    }

    public static void validateResponseOfRolesUpdate(Response response,
                                                     UserDto updater,
                                                     Set<RoleDto> rolesToBeUpdated,
                                                     Set<RoleDto> updateInputs,
                                                     String pathPrefix) {
        if (!pathPrefix.isBlank()) pathPrefix += ".";
        response.then().statusCode(200)
                .body(pathPrefix + "size()", equalTo(rolesToBeUpdated.size()));
        
        var updateInputsMap = updateInputs.stream().collect(Collectors.toMap(RoleDto::getRoleName, Function.identity()));
        for (var role : rolesToBeUpdated) {
            var updateInput = updateInputsMap.getOrDefault(role.getRoleName(), new RoleDto());
            var findPath = pathPrefix + "find { it.roleName == '" + role.getRoleName() + "' }";
            response.then()
                    .body(findPath + "description", updateInput.getDescription() != null ? equalTo(updateInput.getDescription()) : equalTo(role.getDescription()))
                    .body(findPath + "systemRole", equalTo(false))
                    .body(findPath + "updatedBy", equalTo(updater.getUsername()))
                    .body(findPath + "permissions", (updateInput.getPermissions() != null) ?
                            containsInAnyOrder(updateInput.getPermissions().toArray()) :
                            (role.getPermissions() != null) ?
                                    containsInAnyOrder(role.getPermissions().toArray()) :
                                    empty());
        }
    }
}