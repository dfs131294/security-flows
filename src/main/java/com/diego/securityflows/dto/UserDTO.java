package com.diego.securityflows.dto;

import com.diego.securityflows.domain.Role;
import com.diego.securityflows.validation.ValueOfEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDTO {

    @NotEmpty(message = "Email should not be empty")
    @Email(message = "Email must have a valid format")
    private String email;

    @NotEmpty(message = "Firstname should not be empty")
    private String firstname;

    @NotEmpty(message = "Lastname should not be empty")
    private String lastname;

    @NotEmpty(message = "Role should not be empty")
    @ValueOfEnum(enumClass = Role.class, message = "Role should be USER or ADMIN")
    private String role;
}