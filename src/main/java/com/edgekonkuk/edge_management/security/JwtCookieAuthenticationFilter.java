package com.edgekonkuk.edge_management.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** 매 요청마다 서명 쿠키를 검증해 인증 컨텍스트를 세운다. */
@Component
public class JwtCookieAuthenticationFilter extends OncePerRequestFilter {

    private final JwtCookieService jwtCookieService;

    public JwtCookieAuthenticationFilter(JwtCookieService jwtCookieService) {
        this.jwtCookieService = jwtCookieService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            jwtCookieService.readSubject(request).ifPresent(email -> {
                var authentication = new UsernamePasswordAuthenticationToken(
                        email, null, AuthorityUtils.createAuthorityList("ROLE_MEMBER"));
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            });
        }
        filterChain.doFilter(request, response);
    }
}
