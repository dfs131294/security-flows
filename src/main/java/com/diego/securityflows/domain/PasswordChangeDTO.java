package com.diego.securityflows.domain;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PasswordChangeDTO {
    private String oldPassword;
    private String newPassword;
}
