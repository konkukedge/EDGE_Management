package com.edgekonkuk.edge_management.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 구글 로그인 자체는 신원 확인일 뿐이다.
 * 실제 인가는 그 계정이 지정된 드라이브 폴더에 공유되어 있는지로 판단한다.
 */
@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LoginSuccessHandler.class);

    private final DriveAccessChecker driveAccessChecker;
    private final JwtCookieService jwtCookieService;

    public OAuth2LoginSuccessHandler(DriveAccessChecker driveAccessChecker,
                                     JwtCookieService jwtCookieService) {
        this.driveAccessChecker = driveAccessChecker;
        this.jwtCookieService = jwtCookieService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        Object verified = user.getAttribute("email_verified");
        String email = user.getAttribute("email");
        String name = user.getAttribute("name");

        // 구글이 검증하지 않은 이메일은 신원 근거로 쓸 수 없다.
        if (!Boolean.TRUE.equals(verified) || email == null || email.isBlank()) {
            deny(request, response, email, "이메일 미검증");
            return;
        }
        if (!driveAccessChecker.hasAccess(email)) {
            deny(request, response, email, "드라이브 폴더 미공유");
            return;
        }

        log.info("로그인 허용: {}", email);
        jwtCookieService.issue(response, email, name);
        response.sendRedirect(request.getContextPath() + "/");
    }

    private void deny(HttpServletRequest request, HttpServletResponse response, String email, String reason)
            throws IOException {
        log.warn("로그인 거부: email={} 사유={}", email, reason);
        SecurityContextHolder.clearContext();
        jwtCookieService.clear(response);
        response.sendRedirect(request.getContextPath() + "/login.html?denied");
    }
}
