package org.vimal.security.util;

import jakarta.mail.*;
import jakarta.mail.search.*;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Pattern;

public final class EmailReaderUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(EmailReaderUtil.class);

    private static final long DEFAULT_MAX_WAIT_MS = 60000;
    private static final long DEFAULT_POLL_INTERVAL_MS = 3000;
    private static final int DEFAULT_OTP_LENGTH = 6;
    private static final String[] DEFAULT_SEARCH_FOLDERS = {"INBOX", "[Gmail]/Spam"};

    private EmailReaderUtil() {
        throw new AssertionError("Cannot instantiate EmailReaderUtil class");
    }

    public static String getUUIDTypeTokenFromEmail(String email,
                                                   String appPassword,
                                                   String emailSubject) throws Exception {
        var content = fetchParticularEmailContent(email, appPassword, emailSubject, DEFAULT_SEARCH_FOLDERS, DEFAULT_MAX_WAIT_MS, DEFAULT_POLL_INTERVAL_MS, true, true);
        return extractUUIDTypeToken(content);
    }

    public static String getOtpFromEmail(String email,
                                         String appPassword,
                                         String emailSubject) throws Exception {
        var content = fetchParticularEmailContent(email, appPassword, emailSubject, DEFAULT_SEARCH_FOLDERS, DEFAULT_MAX_WAIT_MS, DEFAULT_POLL_INTERVAL_MS, true, true);
        return extractOtp(content);
    }

    public static void assertArgumentsAreNotNullOrBlankBeforeFetchingParticularEmailContent(String email,
                                                                                            String appPassword,
                                                                                            String emailSubject,
                                                                                            String[] folders,
                                                                                            long maxWaitTimeMs,
                                                                                            long intervalTimeMs) {
        if (email == null) throw new RuntimeException("Email cannot be null");
        if (email.isBlank()) throw new RuntimeException("Email cannot be blank");
        if (appPassword == null) throw new RuntimeException("App password cannot be null");
        if (appPassword.isBlank()) throw new RuntimeException("App password cannot be blank");
        if (emailSubject == null) throw new RuntimeException("Email subject cannot be null");
        if (emailSubject.isBlank()) throw new RuntimeException("Email subject cannot be blank");
        if (folders == null) throw new RuntimeException("Folders cannot be null");
        if (folders.length == 0) throw new RuntimeException("Folders cannot be empty");
        for (String folder : folders) {
            if (folder == null) throw new RuntimeException("Folder name cannot be null");
            if (folder.isBlank()) throw new RuntimeException("Folder name cannot be blank");
        }
        if (maxWaitTimeMs < 1) throw new RuntimeException("Max wait time must be greater than 0");
        if (intervalTimeMs < 1) throw new RuntimeException("Interval time must be greater than 0");
    }

    public static String fetchParticularEmailContent(String email,
                                                     String appPassword,
                                                     String emailSubject,
                                                     String[] folders,
                                                     long maxWaitTimeMs,
                                                     long intervalTimeMs,
                                                     boolean seen,
                                                     boolean delete) throws Exception {
        assertArgumentsAreNotNullOrBlankBeforeFetchingParticularEmailContent(email, appPassword, emailSubject, folders, maxWaitTimeMs, intervalTimeMs);
        Properties props = new Properties();
        props.put("mail.store.protocol", "imaps");
        props.put("mail.imaps.host", "imap.gmail.com");
        props.put("mail.imaps.port", "993");
        props.put("mail.imaps.ssl.enable", "true");
        props.put("mail.imaps.timeout", "30000");
        props.put("mail.imaps.connectiontimeout", "30000");
        var session = Session.getInstance(props);
        var store = session.getStore("imaps");
        var searchStartTimeMillis = System.currentTimeMillis();
        var searchStartTime = new Date(searchStartTimeMillis);
        try {
            store.connect(realEmail(email), appPassword);
            while ((System.currentTimeMillis() - searchStartTimeMillis) < maxWaitTimeMs) {
                for (String folderName : folders) {
                    Folder folder = null;
                    try {
                        folder = store.getFolder(folderName);
                        if (!folder.exists()) continue;
                        folder.open(Folder.READ_WRITE);
                        var searchTerm = new AndTerm(new SearchTerm[]{
                                new SubjectTerm(emailSubject),
                                new ReceivedDateTerm(ComparisonTerm.GE, searchStartTime),
                                new RecipientStringTerm(Message.RecipientType.TO, email)
                        });
                        var messages = folder.search(searchTerm);
                        Arrays.sort(messages, Comparator.comparing((Message m) -> {
                            try {
                                return Optional.ofNullable(m.getReceivedDate()).orElse(m.getSentDate());
                            } catch (MessagingException e) {
                                return new Date(0);
                            }
                        }).reversed());
                        for (Message message : messages) {
                            if (message.getReceivedDate() != null && message.getReceivedDate().before(searchStartTime))
                                continue;
                            var content = getTextFromMessage(message);
                            if (seen) message.setFlag(Flags.Flag.SEEN, true);
                            if (delete) {
                                message.setFlag(Flags.Flag.DELETED, true);
                                folder.expunge();
                            }
                            return content;
                        }
                    } catch (Exception ignored) {
                    } finally {
                        if (folder != null && folder.isOpen()) folder.close(true);
                    }
                }
                LOGGER.info("No email found with subject '{}' yet, waiting for {} ms before retrying", emailSubject, intervalTimeMs);
                Thread.sleep(intervalTimeMs);
            }
            throw new RuntimeException("No email found with subject '" + emailSubject + "' after " + searchStartTime);
        } finally {
            if (store != null && store.isConnected()) store.close();
        }
    }

    public static String realEmail(String email) {
        if (email == null) throw new RuntimeException("Alias email cannot be null");
        if (email.isBlank()) throw new RuntimeException("Alias email cannot be blank");
        int atIndex = email.indexOf('@');
        if (atIndex < 0) throw new RuntimeException("Invalid alias email format: " + email);
        String localPart = email.substring(0, atIndex);
        String domainPart = email.substring(atIndex + 1);
        return localPart.split("\\+")[0] + "@" + domainPart;
    }

    public static String getTextFromMessage(Message message) throws Exception {
        if (message.isMimeType("text/plain")) return message.getContent().toString();
        else if (message.isMimeType("multipart/*")) {
            var multipart = (Multipart) message.getContent();
            for (int i = 0; i < multipart.getCount(); i++) {
                var bodyPart = multipart.getBodyPart(i);
                if (bodyPart.isMimeType("text/plain")) return bodyPart.getContent().toString();
                else if (bodyPart.isMimeType("text/html")) return Jsoup.parse(bodyPart.getContent().toString()).text();
            }
        }
        throw new RuntimeException("Unsupported email content format");
    }

    public static void assertContentNotNullOrBlank(String content) {
        if (content == null) throw new RuntimeException("Email content cannot be null");
        if (content.isBlank()) throw new RuntimeException("Email content cannot be blank");
    }

    public static String extractUUIDTypeToken(String content) {
        assertContentNotNullOrBlank(content);
        content = content.replaceAll("\\s+", " ").trim();
        var pattern = Pattern.compile("([a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12})", Pattern.CASE_INSENSITIVE);
        var matcher = pattern.matcher(content);
        if (matcher.find()) return matcher.group(1);
        throw new RuntimeException("UUID type token not found in email content");
    }

    public static String extractOtp(String content) {
        return extractOtp(content, DEFAULT_OTP_LENGTH);
    }

    public static String extractOtp(String content, int otpLength) {
        assertContentNotNullOrBlank(content);
        if (otpLength < 1) throw new RuntimeException("OTP length must be greater than 0");
        content = content.replaceAll("\\s+", " ").trim();
        var pattern = Pattern.compile("\\b(?:OTP[:\\s]*)?(\\d{" + otpLength + "})\\b");
        var matcher = pattern.matcher(content);
        if (matcher.find()) return matcher.group(1);
        throw new RuntimeException("OTP not found in email content");
    }
}