package com.diego.securityflows.validation;

import com.diego.securityflows.validation.ValueOfEnum.List;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.FIELD, ElementType.ANNOTATION_TYPE, ElementType.CONSTRUCTOR, ElementType.PARAMETER, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Constraint(validatedBy = { ValueOfEnumValidator.class, ValueOfEnumListValidator.class })
@Repeatable(List.class)
public @interface ValueOfEnum {

    Class<? extends Enum<?>> enumClass();

    String message() default "Invalid Value";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    @Target({ElementType.METHOD, ElementType.FIELD, ElementType.ANNOTATION_TYPE, ElementType.CONSTRUCTOR, ElementType.PARAMETER, ElementType.TYPE_USE})
    @Retention(RetentionPolicy.RUNTIME)
    @Documented
    public @interface List {
        ValueOfEnum[] value();
    }
}
