package com.diego.securityflows.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;
import java.util.Map;

@Data
@Builder
public class SecurityFlowsExceptionDTO {

    private final String message;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final Map<String, String> errors;

    private final HttpStatus httpStatus;

    private final ZonedDateTime timestamp;
}
