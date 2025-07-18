package org.vimal.security.util;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.time.Instant;

public final class TOTPUtil {
    private static final Base32 base32 = new Base32();
    private static final TimeBasedOneTimePasswordGenerator totpGenerator = new TimeBasedOneTimePasswordGenerator();

    private TOTPUtil() {
        throw new AssertionError("Cannot instantiate TOTPUtil class");
    }

    public static String generateCode(String secret) throws InvalidKeyException {
        return generateCode(secret, Instant.now());
    }

    public static String generateCode(String secret,
                                      Instant timestamp) throws InvalidKeyException {
        if (secret == null) throw new RuntimeException("Secret cannot be null");
        if (secret.isEmpty()) throw new RuntimeException("Secret cannot be empty");
        byte[] keyBytes = base32.decode(secret);
        SecretKey key = new SecretKeySpec(keyBytes, totpGenerator.getAlgorithm());
        int code = totpGenerator.generateOneTimePassword(key, timestamp);
        return String.format("%06d", code);
    }
}