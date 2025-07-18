package org.vimal.security.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class DateTimeUtil {
    private static final DateTimeFormatter DEFAULT_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS");

    private DateTimeUtil() {
        throw new AssertionError("Cannot instantiate DateTimeUtil class");
    }

    public static String getCurrentFormattedTimestampLocal() {
        return getCurrentFormattedTimestampLocal(DEFAULT_FORMATTER);
    }

    public static String getCurrentFormattedTimestampLocal(DateTimeFormatter formatter) {
        return LocalDateTime.now().format(formatter);
    }
}