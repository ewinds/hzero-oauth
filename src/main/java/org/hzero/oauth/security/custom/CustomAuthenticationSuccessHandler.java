package org.hzero.oauth.security.custom;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import org.hzero.oauth.security.config.SecurityProperties;
import org.hzero.oauth.security.event.LoginEvent;
import org.hzero.oauth.security.util.RequestUtil;

/**
 * 登录成功处理器
 *
 * @author bojiangzhou 2019/02/25
 */
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler implements ApplicationContextAware {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private final SecurityProperties securityProperties;

    private ApplicationContext applicationContext;

    public CustomAuthenticationSuccessHandler(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // 发布登录成功事件
        LoginEvent loginEvent = new LoginEvent(request);
        applicationContext.publishEvent(loginEvent);

        super.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String targetUrl = RequestUtil.getBaseURL(request) + "/oauth/authorize" +
                "?response_type=token" +
                "&client_id=" + securityProperties.getLogin().getDefaultClientId() +
                "&redirect_uri=" + securityProperties.getLogin().getSuccessUrl();
        LOGGER.debug("Using default authorize target url: [{}]", targetUrl);
        return targetUrl;
    }

    protected SecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}


