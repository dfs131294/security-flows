package com.diego.securityflows.dto;

import com.diego.securityflows.domain.Role;
import com.diego.securityflows.validation.UniqueValues;
import com.diego.securityflows.validation.ValueOfEnum;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import java.io.Serializable;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class UserDTO implements Serializable {

    private static final long serialVersionUID = 7156526077883281623L;

    @NotEmpty(message = "Email should not be empty")
    @Email(message = "Email must have a valid format")
    private String email;

    @NotEmpty(message = "Firstname should not be empty")
    private String firstname;

    @NotEmpty(message = "Lastname should not be empty")
    private String lastname;

    @NotEmpty(message = "Role should not be empty")
    @UniqueValues(message = "Roles should be unique")
    @ValueOfEnum(enumClass = Role.class, message = "Roles should be %s")
    private List<String> roles;
}
