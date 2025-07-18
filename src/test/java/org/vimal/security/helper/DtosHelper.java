package org.vimal.security.helper;

import org.vimal.security.BaseTest;
import org.vimal.security.dto.RoleDto;
import org.vimal.security.dto.UserDto;
import org.vimal.security.util.DateTimeUtil;
import org.vimal.security.util.RandomStringUtil;

import java.util.HashSet;
import java.util.Set;

public final class DtosHelper {
    private DtosHelper() {
        throw new AssertionError("Cannot instantiate DtosHelper class");
    }

    public static UserDto createRandomUserDto() {
        return createRandomUserDto(null);
    }

    public static Set<UserDto> createRandomUserDtos(int count) {
        var userDtos = new HashSet<UserDto>();
        for (int i = 0; i < count; i++) {
            userDtos.add(createRandomUserDto());
        }
        return userDtos;
    }

    public static UserDto createRandomUserDtoWithRandomValidEmail() {
        return createRandomUserDtoWithGivenEmail(validRandomEmail());
    }

    public static String validRandomEmail() {
        var baseMail = BaseTest.TEST_EMAIL;
        var atIndex = baseMail.indexOf('@');
        var localPart = baseMail.substring(0, atIndex);
        var domainPart = baseMail.substring(atIndex + 1);
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        return localPart + "+" + uniqueString + "@" + domainPart;
    }

    public static UserDto createRandomUserDtoWithGivenEmail(String email) {
        var user = createRandomUserDto(null);
        user.setEmail(email);
        return user;
    }

    public static UserDto createRandomUserDto(Set<String> roles) {
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        return UserDto.builder()
                .username("AutoTestUser_" + uniqueString)
                .email("user_" + uniqueString + "@example.com")
                .password("Password@1_" + uniqueString)
                .firstName("AutoTestUser")
                .roles(roles)
                .emailVerified(true)
                .accountLocked(false)
                .accountEnabled(true)
                .build();
    }

    public static RoleDto createRandomRoleDto() {
        return createRandomRoleDto(null);
    }

    public static Set<RoleDto> createRandomRoleDtos(int count) {
        var roleDtos = new HashSet<RoleDto>();
        for (int i = 0; i < count; i++) {
            roleDtos.add(createRandomRoleDto());
        }
        return roleDtos;
    }

    public static RoleDto createRandomRoleDto(Set<String> permissions) {
        var uniqueString = DateTimeUtil.getCurrentFormattedTimestampLocal() + "_" + RandomStringUtil.generateRandomStringAlphaNumeric();
        return RoleDto.builder()
                .roleName("AutoTestRole_" + uniqueString)
                .description("Auto-generated role for testing purposes")
                .permissions(permissions)
                .build();
    }
}