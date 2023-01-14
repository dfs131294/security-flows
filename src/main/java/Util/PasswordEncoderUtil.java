package Util;

import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordEncoderUtil {

    public static String encode(PasswordEncoder encoder, String password) {
        return encoder.encode(password);
    }
    public static boolean matches(PasswordEncoder encoder, String password, String passwordToMatch) {
        return encoder.matches(password, passwordToMatch);
    }
}
