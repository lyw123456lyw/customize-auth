package com.security.customize.exception.customizeexception;

import com.security.customize.constant.CodeEnum;
import org.springframework.security.access.AccessDeniedException;

import org.springframework.security.core.AuthenticationException;

public class TokenException extends AuthenticationException {

    private static final long serialVersionUID = -8201518085425482189L;

    public TokenException(String msg){
        super(msg);
    }
}
