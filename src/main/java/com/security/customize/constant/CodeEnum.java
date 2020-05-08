package com.security.customize.constant;

public enum CodeEnum {

    TOKENEXPIRED(407,"token失效"),
    TOKENNOEXIST(400,"token不存在"),
    ILLEGALTOKEN(408,"非法token！"),
    TOKENISEMPTY(409,"Token 不能为空");

    private Integer code;
    private String msg;

    private CodeEnum(Integer code,String msg){
        this.code =code;
        this.msg = msg;
    }

    public Integer getCode() {
        return code;
    }
    public void setCode(Integer code) {
        this.code = code;
    }
    public String getMsg() {
        return msg;
    }
    public void setMsg(String msg) {
        this.msg = msg;
    }


}
