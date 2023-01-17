package com.diego.securityflows.validation;

import org.springframework.util.CollectionUtils;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ValueOfEnumValidator implements ConstraintValidator<ValueOfEnum, List<String>> {

    private List<String> acceptedValues;

    @Override
    public void initialize(ValueOfEnum annotation) {
        acceptedValues = Stream.of(annotation.enumClass().getEnumConstants())
                .map(Enum::name)
                .collect(Collectors.toList());
    }

    @Override
    public boolean isValid(List<String> values, ConstraintValidatorContext context) {
        if (CollectionUtils.isEmpty(values)) {
            return true;
        }

        return values.stream()
                .allMatch(av -> acceptedValues.stream()
                        .anyMatch(v -> v.equals(av)));
    }
}