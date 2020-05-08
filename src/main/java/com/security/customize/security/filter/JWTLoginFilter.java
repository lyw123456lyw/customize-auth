package com.security.customize.security.filter;

import com.security.customize.security.authonject.JWTAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义认证规则
 */
public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {
    private String usernameParameter = "username";
    private String passwordParameter = "password";
    private boolean postOnly = true;

    /**
     * 设置该过滤器对POST请求的/login进行拦截
     */
    public JWTLoginFilter(){
        super(new AntPathRequestMatcher("/login","GET"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        if (this.postOnly && !httpServletRequest.getMethod().equals("GET")){
            throw new AuthenticationServiceException("Authentication method not supported: " + httpServletRequest.getMethod());
        }else{
            /**
             * 从http请求中获取用户输入的用户名和密码信息
             */
            String username = this.obtainUsername(httpServletRequest);
            String password = this.obtainPassword(httpServletRequest);
            if (StringUtils.isEmpty(username) && StringUtils.isEmpty(password)) {
                throw new UsernameNotFoundException("JWTLoginFilter获取用户认证信息失败");
            }
            /**
             * 创建一个未认证的用户信息JWTAuthenticationToken去委托自定义的provider认证
             */
            JWTAuthenticationToken jwtToken = new JWTAuthenticationToken(username, password);
            this.setDetails(httpServletRequest,jwtToken);
            /**
             * 委托自定义的provider去认证并返回认证之后的对象
             */
            return this.getAuthenticationManager().authenticate(jwtToken);
        }
    }

    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(this.usernameParameter);
    }

    protected String obtainPassword(HttpServletRequest request) {
        return request.getParameter(this.passwordParameter);
    }

    protected void setDetails(HttpServletRequest request, JWTAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

    public String getUsernameParameter() {
        return usernameParameter;
    }

    public void setUsernameParameter(String usernameParameter) {
        this.usernameParameter = usernameParameter;
    }

    public String getPasswordParameter() {
        return passwordParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        this.passwordParameter = passwordParameter;
    }

    public boolean isPostOnly() {
        return postOnly;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }
}
