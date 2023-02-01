package com.diego.securityflows.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

@Data
@NoArgsConstructor
public class LoginRequestDTO {

    @NotEmpty(message = "Email should not be empty")
    @Email(message = "Email must have a valid format")
    private String email;

    @NotEmpty(message = "Password should not be empty")
    private String password;

    private boolean rememberMe;
}
