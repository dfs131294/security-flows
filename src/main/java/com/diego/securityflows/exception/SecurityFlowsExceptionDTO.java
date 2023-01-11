package com.diego.securityflows.exception;

import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;

@Data
@Builder
public class SecurityFlowsExceptionDTO {
    private final String mensaje;
    private final HttpStatus httpStatus;
    private final ZonedDateTime timestamp;
}
