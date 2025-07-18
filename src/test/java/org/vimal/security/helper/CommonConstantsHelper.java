package org.vimal.security.helper;

public final class CommonConstantsHelper {
    private CommonConstantsHelper() {
        throw new AssertionError("Cannot instantiate CommonConstantsHelper class");
    }

    public static final String AUTHORIZATION_HEADER_PREFIX = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final int MAX_BATCH_SIZE = 100;
}