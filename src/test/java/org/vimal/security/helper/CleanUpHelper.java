package org.vimal.security.helper;

import org.vimal.security.dto.RoleDto;
import org.vimal.security.dto.UserDto;

import java.lang.reflect.Array;
import java.util.HashSet;
import java.util.Set;

public final class CleanUpHelper {
    private CleanUpHelper() {
        throw new AssertionError("Cannot instantiate CleanUpHelper class");
    }

    public static void cleanUpTestUsers(Object... inputs) {
        var usernamesOrEmails = extractUsernamesOrEmails(inputs);
        var iterator = usernamesOrEmails.iterator();
        while (iterator.hasNext()) {
            var batch = new HashSet<String>();
            while (iterator.hasNext() && batch.size() < CommonConstantsHelper.MAX_BATCH_SIZE) {
                batch.add(iterator.next());
            }
            try {
                CallsUsingGlobalAdminUserHelper.deleteUsersLenient(batch);
            } catch (Exception ignored) {
            }
        }
    }

    private static Set<String> extractUsernamesOrEmails(Object... inputs) {
        var result = new HashSet<String>();
        for (Object input : inputs) {
            switch (input) {
                case null -> {
                }
                case String str -> result.add(str);
                case UserDto dto -> extractFromUserDto(dto, result);
                case Iterable<?> iterable -> {
                    for (Object element : iterable) {
                        result.addAll(extractUsernamesOrEmails(element));
                    }
                }
                default -> {
                    if (input.getClass().isArray()) {
                        int length = Array.getLength(input);
                        for (int i = 0; i < length; i++) {
                            Object element = Array.get(input, i);
                            result.addAll(extractUsernamesOrEmails(element));
                        }
                    } else {
                        throw new RuntimeException("Unsupported input type: " + input.getClass());
                    }
                }
            }
        }
        return result;
    }

    private static void extractFromUserDto(UserDto dto, Set<String> result) {
        if (dto == null) return;
        if (dto.getUsername() != null) result.add(dto.getUsername());
        else if (dto.getEmail() != null) result.add(dto.getEmail());
    }

    public static void cleanUpTestRoles(Object... inputs) {
        var roleNames = extractRoleNames(inputs);
        var iterator = roleNames.iterator();
        while (iterator.hasNext()) {
            var batch = new HashSet<String>();
            while (iterator.hasNext() && batch.size() < CommonConstantsHelper.MAX_BATCH_SIZE) {
                batch.add(iterator.next());
            }
            try {
                CallsUsingGlobalAdminUserHelper.deleteRolesLenient(batch);
            } catch (Exception ignored) {
            }
        }
    }

    public static Set<String> extractRoleNames(Object... inputs) {
        var result = new HashSet<String>();
        for (Object input : inputs) {
            switch (input) {
                case null -> {
                }
                case String str -> result.add(str);
                case RoleDto dto -> extractFromRoleDto(dto, result);
                case Iterable<?> iterable -> {
                    for (Object element : iterable) {
                        result.addAll(extractRoleNames(element));
                    }
                }
                default -> {
                    if (input.getClass().isArray()) {
                        int length = Array.getLength(input);
                        for (int i = 0; i < length; i++) {
                            Object element = Array.get(input, i);
                            result.addAll(extractRoleNames(element));
                        }
                    } else {
                        throw new RuntimeException("Unsupported input type: " + input.getClass());
                    }
                }
            }
        }
        return result;
    }

    private static void extractFromRoleDto(RoleDto dto, Set<String> result) {
        if (dto == null) return;
        if (dto.getRoleName() != null) result.add(dto.getRoleName());
    }
}