package com.security.customize.security.authonject;


import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 *框架自带的是一个封装了用户名和密码的UsernamePasswordAuthenticationToken
 * 如果在实际业务中还需要定制一些字段可以在其中添加属性
 */
public class JWTAuthenticationToken extends AbstractAuthenticationToken {
    /**
     * 用户名
     */

    private  final Object principal;
    /**
     *密码
     */

    private Object credentials;

    /**
     * 创建未认证的用户信息
     * @param principal
     * @param credentials
     */
    public JWTAuthenticationToken(Object principal,Object credentials) {
        super((Collection) null);
        this.credentials = credentials;
        this.principal = principal;
        this.setAuthenticated(false);
    }

    /**
     * 创建认证成功的用户信息
     * @param principal
     * @param credentials
     * @param authorities
     */
    public JWTAuthenticationToken(Object principal,Object credentials,Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.credentials = credentials;
        this.principal = principal;
        super.setAuthenticated(true);
    }




    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }


    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated){
            throw new IllegalStateException("Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }else{
            super.setAuthenticated(false);
        }
    }



}
