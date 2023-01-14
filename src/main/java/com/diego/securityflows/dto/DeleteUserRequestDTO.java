package com.diego.securityflows.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

@Data
@NoArgsConstructor
public class DeleteUserRequestDTO {

    @NotEmpty(message = "Email cant be null or empty")
    @Email(message = "Email must and email with a valid format")
    private String username;
}
