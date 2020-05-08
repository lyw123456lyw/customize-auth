package com.security.customize.exception.customizeexception;

import org.springframework.security.access.AccessDeniedException;

import javax.security.sasl.AuthenticationException;

public class AuthticationException extends AccessDeniedException {
    public AuthticationException(String msg) {
        super(msg);
    }
}
