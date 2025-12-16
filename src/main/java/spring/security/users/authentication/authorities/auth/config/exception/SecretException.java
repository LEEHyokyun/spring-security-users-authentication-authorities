package spring.security.users.authentication.authorities.auth.config.exception;

import org.springframework.security.core.AuthenticationException;

public class SecretException extends AuthenticationException {
    public SecretException(String msg) {
        super(msg);
    }
}
