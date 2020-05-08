package com.security.customize.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.customize.constant.CodeEnum;
import com.security.customize.entity.User;
import com.security.customize.exception.customizeexception.ThrowInfo;
import com.security.customize.exception.customizeexception.TokenException;
import com.security.customize.security.authonject.JWTAuthenticationToken;
import com.security.customize.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public class JWTAuthticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private RedisTemplate redisTemplate;
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("token");
        String jsonData;
        if (token == null || token.length() <= 0){
            throw new TokenException(String.valueOf(CodeEnum.TOKENISEMPTY.getCode()));
        }else if (StringUtils.isEmpty((jsonData = (String) redisTemplate.opsForValue().get(token)))){
            throw new TokenException(String.valueOf(CodeEnum.ILLEGALTOKEN.getCode()));
        }else{
            User user = objectMapper.readValue(jsonData, User.class);
            //从redis里面携带的token查出用户信息,并把用户信息放入security中的上下文就可以访问了
            if (user != null && SecurityContextHolder.getContext().getAuthentication() == null){
                JWTAuthenticationToken authentication = new JWTAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request,response);
    }
}
