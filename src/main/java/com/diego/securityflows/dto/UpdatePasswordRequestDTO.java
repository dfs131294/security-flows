package com.diego.securityflows.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

@Data
@NoArgsConstructor
public class UpdatePasswordRequestDTO {

    @NotEmpty(message = "Email should not be empty")
    @Email(message = "Email must have a valid format")
    private String email;

    @NotEmpty(message = "New password should not be empty")
    private String newPassword;
}
