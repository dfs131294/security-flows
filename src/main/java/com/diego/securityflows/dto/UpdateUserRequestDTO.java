package com.diego.securityflows.dto;

import com.diego.securityflows.domain.Role;
import com.diego.securityflows.domain.UserStatus;
import com.diego.securityflows.validation.UniqueValues;
import com.diego.securityflows.validation.ValueOfEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UpdateUserRequestDTO {

    @Email(message = "Email must have a valid format")
    private String email;

    private String firstname;

    private String lastname;

    @UniqueValues(message = "Role should be unique")
    @ValueOfEnum(enumClass = Role.class, message = "Role should be USER or ADMIN")
    private List<String> roles;

    private UserStatus status;
}
