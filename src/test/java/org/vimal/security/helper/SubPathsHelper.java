package org.vimal.security.helper;

public final class SubPathsHelper {
    private SubPathsHelper() {
        throw new AssertionError("Cannot instantiate SubPathsHelper class");
    }

    public static final String AUTH_SUB_PATH = "/auth";
    public static final String USER_SUB_PATH = "/user";
    public static final String ADMIN_SUB_PATH = "/admin";
    public static final String USER_ADMIN_SUB_PATH = USER_SUB_PATH + ADMIN_SUB_PATH;
    public static final String USER_SELF_SUB_PATH = USER_SUB_PATH + "/self";
    public static final String MFA_SUB_PATH = "/mfa";
}