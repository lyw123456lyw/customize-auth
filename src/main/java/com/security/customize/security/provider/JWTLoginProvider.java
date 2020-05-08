package com.security.customize.security.provider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.customize.constant.Constant;
import com.security.customize.security.authonject.JWTAuthenticationToken;
import com.security.customize.service.UserService;
import com.security.customize.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 自定义委托认证类
 */
@Component
public class JWTLoginProvider implements AuthenticationProvider {
    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RedisTemplate redisTemplate;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //将委托过来的认证信息转化成我们自己定义的
        JWTAuthenticationToken unAuthToken = (JWTAuthenticationToken)authentication;
        UserDetails userDetails = userService.loadUserByUsername(unAuthToken.getName());
        if (userDetails == null){
            throw new InternalAuthenticationServiceException("JWTLoginProvider获取认证用户信息失败");
        }else if (!this.passwordEncoder.matches((CharSequence) unAuthToken.getCredentials(), userDetails.getPassword())){
            throw new BadCredentialsException("用户名或密码不正确");
        }
        //认证成功之后重新封装用户信息返回Authentication对象
        JWTAuthenticationToken authToken = new JWTAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
        authToken.setDetails(unAuthToken.getDetails());
        //给JWT赋予用户信息
        Map<String, String> userInfo = createUserInfoMap(userDetails.getUsername(), this.passwordEncoder.encode((CharSequence) unAuthToken.getCredentials()));
        //创建 hour小时后过期的Token
        String token = jwtUtils.createToken(userInfo, 1);
        String jsonData = null;
        try {
            jsonData = objectMapper.writeValueAsString(userDetails);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        System.out.println(token);
        //将token存入redis
        redisTemplate.opsForValue().set(token,jsonData);
        redisTemplate.expire(token, Constant.TOKEN_EXPIRE,TimeUnit.HOURS);
        return authToken;
    }

    private Map<String,String> createUserInfoMap(String loginName, String password) {
        Map<String,String> userInfo = new HashMap<String,String>();
        userInfo.put("loginName", loginName);
        userInfo.put("password", password);
        return userInfo;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return JWTAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
