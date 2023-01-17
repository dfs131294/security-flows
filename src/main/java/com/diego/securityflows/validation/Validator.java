package com.diego.securityflows.validation;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
@Component
public class Validator {

    private static final String ERRORS_DELIMITER = ", ";
    private final javax.validation.Validator validator;

    public <T> void validate(T o) {
        final Set<ConstraintViolation<T>> violations = validator.validate(o);
        if (!violations.isEmpty()) {
            final String errors = violations.stream()
                    .map(ConstraintViolation::getMessage)
                    .collect(Collectors.joining(ERRORS_DELIMITER));
            throw new ConstraintViolationException(errors, violations);
        }
    }
}
