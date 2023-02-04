package com.diego.securityflows.domain;

public enum UserStatus {

    INACTIVE(0),
    ACTIVE(1);

    private Integer code;

    UserStatus(int code) {
        this.code = code;
    }
}
