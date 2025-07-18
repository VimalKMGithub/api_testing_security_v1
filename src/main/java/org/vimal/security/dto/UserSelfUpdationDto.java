package org.vimal.security.dto;

import lombok.*;

@Getter
@Setter
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class UserSelfUpdationDto {
    private String firstName;
    private String middleName;
    private String lastName;
    private String oldPassword;
    private String username;
    private String newPassword;
    private String confirmNewPassword;
}