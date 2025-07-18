package org.vimal.security.util;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.Map;

public final class QRUtil {
    private QRUtil() {
        throw new AssertionError("Cannot instantiate QRUtil class");
    }

    public static String extractSecretFromQRImage(byte[] qrCodeImage) throws IOException, NotFoundException {
        String totpUrl = decodeQRCode(qrCodeImage);
        return extractSecretFromTOTPUrl(totpUrl);
    }

    public static String decodeQRCode(byte[] qrCodeImage) throws IOException, NotFoundException {
        if (qrCodeImage == null) throw new RuntimeException("QR code image cannot be null");
        if (qrCodeImage.length == 0) throw new RuntimeException("QR code image cannot be empty");
        BufferedImage bufferedImage = ImageIO.read(new ByteArrayInputStream(qrCodeImage));
        if (bufferedImage == null) throw new IOException("Unable to decode QR image into BufferedImage");
        LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        Result result = new MultiFormatReader().decode(bitmap, hints);
        return result.getText();
    }

    public static String extractSecretFromTOTPUrl(String totpUrl) {
        if (!isValidTOTPUrl(totpUrl)) throw new RuntimeException("Invalid TOTP URL format");
        int queryStart = totpUrl.indexOf('?');
        if (queryStart == -1) throw new RuntimeException("No query parameters found in TOTP URL");
        if (queryStart == totpUrl.length() - 1) throw new RuntimeException("No parameters found in TOTP URL");
        String[] params = totpUrl.substring(queryStart + 1).split("&");
        for (String param : params)
            if (param.startsWith("secret=")) return URLDecoder.decode(param.substring(7), StandardCharsets.UTF_8);
        throw new RuntimeException("No secret parameter found in TOTP URL");
    }

    public static boolean isValidTOTPUrl(String totpUrl) {
        return totpUrl != null && totpUrl.startsWith("otpauth://totp/") && totpUrl.contains("secret=");
    }
}