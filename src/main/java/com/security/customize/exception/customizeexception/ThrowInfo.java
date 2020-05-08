package com.security.customize.exception.customizeexception;

import lombok.Data;

@Data
public class ThrowInfo extends Throwable {
    private Integer code;
}
