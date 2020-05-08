//package com.security.customize.exception;
//
//import com.security.customize.exception.customizeexception.TokenException;
//import com.security.customize.exception.message.ReturnMessage;
//import com.security.customize.utils.ReturnMessageUtil;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.web.bind.annotation.ExceptionHandler;
//import org.springframework.web.bind.annotation.RestControllerAdvice;
//
//import javax.servlet.http.HttpServletResponse;
//@RestControllerAdvice
//public class ExceptionHandle {
//    private final static Logger logger = LoggerFactory.getLogger(ExceptionHandle.class);
//
////    @ExceptionHandler(value = Exception.class)
////    public ReturnMessage<Object> handle(HttpServletResponse response, Exception exception) {
////        response.setCharacterEncoding("utf-8");
////        if(exception instanceof TokenException) {
////            TokenException tokenException = (TokenException)exception;
////            return ReturnMessageUtil.error(tokenException.getCode(), tokenException.getMessage());
////        }else {
////            logger.error("系统异常 {}",exception);
////            return ReturnMessageUtil.error(-1, "未知异常"+exception.getMessage());
////        }
////    }
//}
