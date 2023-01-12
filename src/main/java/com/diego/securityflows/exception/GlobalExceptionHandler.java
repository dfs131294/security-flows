package com.diego.securityflows.exception;

import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.ZonedDateTime;
import java.util.Map;
import java.util.stream.Collectors;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final String INVALID_JWT_TOKEN_MESSAGE = "Invalid JWT Token";
    private static final String INVALID_PAYLOAD_MESSAGE = "Invalid Payload";

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<Object> handleJwtException(Exception ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(SecurityFlowsExceptionDTO.builder()
                        .httpStatus(HttpStatus.UNAUTHORIZED)
                        .message(INVALID_JWT_TOKEN_MESSAGE)
                        .timestamp(ZonedDateTime.now())
                        .build());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Object> handleIllegalArgumentException(Exception ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(SecurityFlowsExceptionDTO.builder()
                        .httpStatus(HttpStatus.BAD_REQUEST)
                        .message(ex.getMessage())
                        .timestamp(ZonedDateTime.now())
                        .build());
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers, HttpStatus status, WebRequest request) {
        Map<String, String> errors = ex.getBindingResult()
                .getAllErrors()
                .stream()
                .collect(Collectors.toMap(
                        error -> ((FieldError) error).getField(),
                        error -> StringUtils.hasText(error.getDefaultMessage()) ? error.getDefaultMessage() : "")
                );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(SecurityFlowsExceptionDTO.builder()
                        .httpStatus(HttpStatus.BAD_REQUEST)
                        .message(INVALID_PAYLOAD_MESSAGE)
                        .errors(errors)
                        .timestamp(ZonedDateTime.now())
                        .build());
    }
}
