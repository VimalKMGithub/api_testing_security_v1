package org.vimal.security.dto;

import lombok.*;

@Getter
@Setter
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class ResetPwdDto {
    private String username;
    private String email;
    private String usernameOrEmail;
    private String otp;
    private String password;
    private String oldPassword;
    private String newPassword;
    private String confirmPassword;
}