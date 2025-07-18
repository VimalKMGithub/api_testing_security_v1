package org.vimal.security.util;

import java.util.concurrent.ThreadLocalRandom;

public final class RandomStringUtil {
    private static final int DEFAULT_LENGTH = 10;
    private static final String ALPHA_NUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private RandomStringUtil() {
        throw new AssertionError("Cannot instantiate RandomStringUtil class");
    }

    public static String generateRandomStringAlphaNumeric() {
        return generateRandomString(ALPHA_NUMERIC, DEFAULT_LENGTH);
    }

    public static String generateRandomString(String characters,
                                              int length) {
        if (length < 1) throw new RuntimeException("Length must be positive to generate a random string");
        if (characters == null) throw new RuntimeException("Character set must not be null");
        if (characters.isEmpty()) throw new RuntimeException("Character set must not be empty");
        StringBuilder sb = new StringBuilder(length);
        ThreadLocalRandom random = ThreadLocalRandom.current();
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            sb.append(characters.charAt(index));
        }
        return sb.toString();
    }
}