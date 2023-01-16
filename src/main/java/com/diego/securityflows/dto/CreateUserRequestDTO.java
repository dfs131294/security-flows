package com.diego.securityflows.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotEmpty;

@Data
@NoArgsConstructor
public class CreateUserRequestDTO extends UserDTO {

    @NotEmpty(message = "Password should not be empty")
    private String password;
}
