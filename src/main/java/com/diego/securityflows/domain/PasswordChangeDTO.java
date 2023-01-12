package com.diego.securityflows.domain;

import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotEmpty;

@Data
@Builder
public class PasswordChangeDTO {

    @NotEmpty(message = "Old password should not be empty")
    private String oldPassword;

    @NotEmpty(message = "New password should not be empty")
    private String newPassword;
}
