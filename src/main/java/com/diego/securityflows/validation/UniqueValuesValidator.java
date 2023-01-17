package com.diego.securityflows.validation;

import org.springframework.util.CollectionUtils;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.List;
import java.util.stream.Collectors;

public class UniqueValuesValidator implements ConstraintValidator<UniqueValues, List<String>> {

    @Override
    public boolean isValid(List<String> values, ConstraintValidatorContext context) {
        if (CollectionUtils.isEmpty(values)) {
            return true;
        }

        final List<String> distinctValues = values.stream()
                .distinct()
                .collect(Collectors.toList());
        return values.size() == distinctValues.size();
    }
}
