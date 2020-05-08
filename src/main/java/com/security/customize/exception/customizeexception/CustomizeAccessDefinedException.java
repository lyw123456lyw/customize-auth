package com.security.customize.exception.customizeexception;

import org.springframework.security.access.AccessDeniedException;

public class CustomizeAccessDefinedException extends AccessDeniedException {

    public CustomizeAccessDefinedException(String msg) {
        super(msg);
    }
}
