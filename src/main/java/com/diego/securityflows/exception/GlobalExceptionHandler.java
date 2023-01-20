package com.diego.securityflows.exception;

import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.internal.engine.ConstraintViolationImpl;
import org.hibernate.validator.internal.metadata.descriptor.ConstraintDescriptorImpl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.lang.annotation.Annotation;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final String INVALID_JWT_TOKEN_MESSAGE = "Invalid JWT Token";
    private static final String INVALID_PAYLOAD_MESSAGE = "Invalid Payload";
    private static final String USER_NOT_FOUND_MESSAGE = "User with username '%s' not found";
    private static final String UNAUTHORIZED_MESSAGE = "UNAUTHORIZED";
    private static final String ENUM_VALIDATOR_ANNOTATION = "ValueOfEnum";
    private static final String ENUM_INVALID_MESSAGE_SEPARATOR_DELIMITER = ", ";
    private static final String ENUM_INVALID_MESSAGE_SEPARATOR_CONJUNCTION = " OR ";

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<Object> handleJwtException(Exception ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(SecurityFlowsExceptionDTO.builder()
                        .httpStatus(HttpStatus.UNAUTHORIZED)
                        .message(INVALID_JWT_TOKEN_MESSAGE)
                        .timestamp(ZonedDateTime.now())
                        .build());
    }

    @ExceptionHandler({ IllegalArgumentException.class, SecurityFlowException.class })
    public ResponseEntity<Object> handleIllegalArgumentException(Exception ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(SecurityFlowsExceptionDTO.builder()
                        .httpStatus(HttpStatus.BAD_REQUEST)
                        .message(ex.getMessage())
                        .timestamp(ZonedDateTime.now())
                        .build());
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Object> handleUsernameNotFoundException(Exception ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(SecurityFlowsExceptionDTO.builder()
                        .httpStatus(HttpStatus.BAD_REQUEST)
                        .message(String.format(USER_NOT_FOUND_MESSAGE, ex.getMessage()))
                        .timestamp(ZonedDateTime.now())
                        .build());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDeniedException(Exception ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(SecurityFlowsExceptionDTO.builder()
                        .httpStatus(HttpStatus.UNAUTHORIZED)
                        .message(UNAUTHORIZED_MESSAGE)
                        .timestamp(ZonedDateTime.now())
                        .build());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Object> handleBadCredentialsException(Exception ex, WebRequest request) {
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
        final Map<String, String> errors = ex.getBindingResult()
                .getAllErrors()
                .stream()
                .collect(Collectors.toMap(this.getKeyFromError(), this.getValueFromError()));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(SecurityFlowsExceptionDTO.builder()
                        .httpStatus(HttpStatus.BAD_REQUEST)
                        .message(INVALID_PAYLOAD_MESSAGE)
                        .errors(errors)
                        .timestamp(ZonedDateTime.now())
                        .build());
    }

    private Function<ObjectError, String> getKeyFromError() {
        return error -> ((FieldError) error).getField();
    }

    private Function<ObjectError, String> getValueFromError() {
        return error -> {
            final String message = error.getDefaultMessage();
            if (!StringUtils.hasText(message)) {
                return "";
            }

            if (Objects.nonNull(error.getCodes())) {
                final boolean comesFromValueOfEnumAnnotation = Arrays.stream(error.getCodes())
                        .anyMatch(c -> c.contains(ENUM_VALIDATOR_ANNOTATION));
                if (comesFromValueOfEnumAnnotation) {
                    final Class<?> enumClass = this.getEnumClass(error);
                    final List<String> enumConstants = this.getEnumConstants(enumClass);
                    if (CollectionUtils.isEmpty(enumConstants)) {
                        return message.replaceAll("%s", "");
                    }

                    if (enumConstants.size() == 1){
                        return String.format(message, String.join("", enumConstants));
                    }

                    final String joinedEnumConstants = this.joinEnumConstants(enumConstants);
                    return String.format(message, joinedEnumConstants);
                }
            }

            return message;
        };
    }

    @SuppressWarnings({ "unchecked" })
    private Class<?> getEnumClass(ObjectError error) {
        return (Class<?>) ((ConstraintDescriptorImpl<Annotation>) error.unwrap(ConstraintViolationImpl.class)
                .getConstraintDescriptor())
                .getAnnotationDescriptor()
                .getAttributes()
                .get("enumClass");
    }

    private List<String> getEnumConstants(Class<?> enumClass) {
        return Arrays.stream(enumClass.getEnumConstants())
                .map(Object::toString)
                .collect(Collectors.toList());
    }

    private String joinEnumConstants(List<String> enumConstants) {
        final String joinedByConjunction = String.join(ENUM_INVALID_MESSAGE_SEPARATOR_CONJUNCTION,
                enumConstants.subList(enumConstants.size() - 2, enumConstants.size()));
        if (enumConstants.size() == 2) {
            return joinedByConjunction;
        }

        final String joinedByCommas = String.join(ENUM_INVALID_MESSAGE_SEPARATOR_DELIMITER,
                enumConstants.subList(0, enumConstants.size() - 2));
        return String.format("%s, %s", joinedByCommas, joinedByConjunction);
    }
}
