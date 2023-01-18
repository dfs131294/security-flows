package com.diego.securityflows.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import javax.validation.constraints.NotEmpty;

@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class CreateUserRequestDTO extends UserDTO {

    @NotEmpty(message = "Password should not be empty")
    private String password;
}
