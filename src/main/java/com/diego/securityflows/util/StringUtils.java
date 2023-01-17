package com.diego.securityflows.util;

import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.List;

public class StringUtils {

    public static String getNonEmptyValue(String v1, String v2) {
        if (org.springframework.util.StringUtils.hasText(v1)) {
            return v1;
        }
        if (org.springframework.util.StringUtils.hasText(v2)) {
            return v2;
        }
        return null;
    }

    public static List<String> getNonEmptyValues(List<String> v1, List<String> v2) {
        if (!CollectionUtils.isEmpty(v1)) {
            return v1;
        }
        if (!CollectionUtils.isEmpty(v2)) {
            return v2;
        }
        return Collections.EMPTY_LIST;
    }
}
