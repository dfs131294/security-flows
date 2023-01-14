package com.diego.securityflows.exception;

import lombok.Data;

import java.time.ZonedDateTime;

@Data
public class SecurityFlowException extends RuntimeException {
    private ZonedDateTime timestamp;

    public SecurityFlowException(String message){
        super(message);
        this.timestamp = ZonedDateTime.now();
    }
}
