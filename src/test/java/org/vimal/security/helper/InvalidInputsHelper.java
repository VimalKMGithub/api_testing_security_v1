package org.vimal.security.helper;

import java.util.HashSet;
import java.util.Set;

public final class InvalidInputsHelper {
    private InvalidInputsHelper() {
        throw new AssertionError("Cannot instantiate MapOfInvalidInputsWithResultHelper class");
    }

    public static Set<String> invalidUsernames() {
        return Set.of(
                "",
                " ",
                "a",
                "ab",
                "a".repeat(101),
                "ab cd",
                "ab@cd",
                "ab#cd"
        );
    }

    public static Set<String> invalidPasswords() {
        return Set.of(
                "",
                " ",
                "short",
                "s".repeat(256),
                "12345678",
                "12345678!",
                "abcdefgh",
                "abcdefgh1",
                "abcdefgh!",
                "abcdefgh!1",
                "ABCDEFGH",
                "ABCDEFGH!",
                "ABCDEFGH1",
                "ABCDEFGH!1",
                "!@#$%^&*",
                "1234ABCD",
                "abcdABCD",
                "abcd1234",
                "ABCD1234",
                "ABCD!@#$",
                "abcd!@#$"
        );
    }

    public static Set<String> invalidEmails() {
        return Set.of(
                "",
                " ",
                "plainaddress",
                "@no-local-part.com",
                "Outlook Contact <outlook-contact@domain.com>",
                "no-at.domain.com",
                "no-tld@domain",
                "semicolon@domain.com;",
                "user@.com",
                "user@domain..com",
                "user@-domain.com",
                "user@domain-.com",
                "user@domain.c",
                "a".repeat(255) + "@test.com",
                "a".repeat(65) + "@test.com",
                ".abc@test.com",
                "ab..cd@test.com",
                "user@domain.c1",
                "user@domain." + "a".repeat(191)
        );
    }

    public static Set<String> invalidUuids() {
        return Set.of(
                "",
                " ",
                "   ",
                "\t",
                "\n",
                "123",
                "abc-def",
                "12345678-1234-1234-1234-123456789",
                "12345678-1234-1234-1234-12345678901234",
                "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
                "00000000-0000-0000-0000-0000000000000",
                "00000000-0000-0000-0000-00000000",
                "g2345678-1234-1234-1234-123456789012",
                "12345678-1234-6234-8234-123456789012",
                "12345678-1234-1234-7234-123456789012",
                " 12345678-1234-1234-1234-123456789012 ",
                "\n12345678-1234-1234-1234-123456789012\n"
        );
    }

    public static Set<String> invalidOTPs() {
        return Set.of(
                "",
                " ",
                "   ",
                "\t",
                "\n",
                "123",
                "1234567",
                "123456789",
                "abcdef",
                "ABCDEF",
                "12ABCD",
                "12!@#",
                "12 34",
                "12-34",
                "12_34",
                "12345678a",
                "12345678A",
                "12345678!",
                "12345678@",
                "１２３４５６",
                "١٢٣٤٥٦",
                "1234🙂",
                "🙂🙂🙂🙂🙂🙂",
                " 123456",
                "123456 ",
                "\n123456",
                "\t123456"
        );
    }

    public static Set<String> invalidNames() {
        return Set.of(
                "",
                " ",
                "F".repeat(51),
                "F1",
                "F!",
                "F!1"
        );
    }

    public static Set<String> commonInvalidRoleNamesPermissionNames() {
        return Set.of(
                "",                        // blank
                " ",                       // space only
                "perm name",               // space inside
                "perm-name",               // hyphen
                "perm.name",               // dot
                "perm@name",               // special char @
                "perm#name",               // special char #
                "perm$name",               // special char $
                "perm%name",               // special char %
                "perm^name",               // special char ^
                "perm&name",               // special char &
                "perm*name",               // special char *
                "perm(name)",              // parentheses
                "perm+name",               // plus sign
                "perm=name",               // equal sign
                "perm~name",               // tilde
                "perm/name",               // slash
                "perm\\name",              // backslash
                "perm,name",               // comma
                "perm;name",               // semicolon
                "perm:name",               // colon
                "perm!name",               // exclamation mark
                "perm?name",               // question mark
                "perm\"name\"",            // double quotes
                "'permname'",              // single quotes
                "perm'name",               // mixed quote
                "perm🙂name"              // emoji / Unicode symbol
        );
    }

    public static Set<String> invalidPermissionNames() {
        var invalidPermissionNames = new HashSet<>(commonInvalidRoleNamesPermissionNames());
        invalidPermissionNames.add("a".repeat(101)); // exceeds max length (101 chars)
        return invalidPermissionNames;
    }

    public static Set<String> invalidRoleNames() {
        var invalidRoleNames = new HashSet<>(commonInvalidRoleNamesPermissionNames());
        invalidRoleNames.add("a".repeat(51)); // exceeds max length (51 chars)
        return invalidRoleNames;
    }
}