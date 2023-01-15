package com.diego.securityflows.dto;

import com.diego.securityflows.domain.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponseDTO {

    private String username;
    private String firstName;
    private String lastName;
    private Role role;
}
