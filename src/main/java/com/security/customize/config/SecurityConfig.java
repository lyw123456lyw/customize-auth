package com.security.customize.config;

import com.security.customize.exception.customizeexception.CustomizeAccessDefinedException;
import com.security.customize.exception.customizeexception.CustomizeAccessDeniedHandler;
import com.security.customize.exception.customizeexception.MyAuthenticationEntryPoint;
import com.security.customize.exception.customizeexception.TokenExceptionHandler;
import com.security.customize.security.config.JWTAuthenticationConfig;
import com.security.customize.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.rmi.CORBA.ClassDesc;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private TokenExceptionHandler tokenExceptionHandler;
    @Autowired
    private CustomizeAccessDeniedHandler customizeAccessDeniedHandler;
    /**
     * 密码加密器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        //BCryptPasswordEncoder：相同的密码明文每次生成的密文都不同，安全性更高
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private UserService userDetailsServiceImpl;

    @Autowired
    private JWTAuthenticationConfig jwtAuthenticationConfig;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //设置自定义登录验证
        auth.userDetailsService(userDetailsServiceImpl);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
        csrf().disable().apply(jwtAuthenticationConfig)
        .and()
        .authorizeRequests().antMatchers("/login/**").permitAll().anyRequest().authenticated()
        .and()
        .exceptionHandling().accessDeniedHandler(customizeAccessDeniedHandler).authenticationEntryPoint(tokenExceptionHandler);


    }
}
