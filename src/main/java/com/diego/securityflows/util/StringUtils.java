package com.diego.securityflows.util;

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
}
