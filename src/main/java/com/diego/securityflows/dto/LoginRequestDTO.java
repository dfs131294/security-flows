package com.diego.securityflows.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

@Data
@NoArgsConstructor
public class LoginRequestDTO {

    @NotEmpty(message = "Email cant be null or empty")
    @Email(message = "Email must have a valid format")
    private String username;

    @NotEmpty(message = "Username cant be null or empty")
    private String password;
}
