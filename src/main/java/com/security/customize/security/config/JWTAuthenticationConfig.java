package com.security.customize.security.config;

import com.security.customize.security.filter.JWTAuthticationTokenFilter;
import com.security.customize.security.filter.JWTLoginFilter;
import com.security.customize.security.handle.JWTFailureHandle;
import com.security.customize.security.handle.JWTSuccessHandle;
import com.security.customize.security.provider.JWTLoginProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@Component
public class JWTAuthenticationConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    @Autowired
    private JWTSuccessHandle jwtSuccessHandle;
    @Autowired
    private JWTFailureHandle jwtFailureHandle;
    @Autowired
    private JWTLoginProvider jwtLoginProvider;
    @Autowired
    private JWTAuthticationTokenFilter jwtAuthticationTokenFilter;
    @Override
    public void configure(HttpSecurity http) throws Exception {
        JWTLoginFilter loginFilter = new JWTLoginFilter();
        JWTAuthticationTokenFilter jwtAuthticationTokenFilter = new JWTAuthticationTokenFilter();
        //自定义用户认证处理逻辑时，需要指定AuthenticationManager，否则无法认证
        loginFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        //指定自定义的认证成功和失败的处理器
        loginFilter.setAuthenticationSuccessHandler(jwtSuccessHandle);
        loginFilter.setAuthenticationFailureHandler(jwtFailureHandle);
        //把自定义的用户名密码认证过滤器和处理器添加到UsernamePasswordAuthenticationFilter过滤器之前
        http.authenticationProvider(jwtLoginProvider)
                .addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(this.jwtAuthticationTokenFilter,UsernamePasswordAuthenticationFilter.class);
    }
}
