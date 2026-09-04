package com.edgekonkuk.edge_management.config;

import com.edgekonkuk.edge_management.security.JwtCookieAuthenticationFilter;
import com.edgekonkuk.edge_management.security.JwtCookieService;
import com.edgekonkuk.edge_management.security.OAuth2LoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtCookieAuthenticationFilter jwtCookieAuthenticationFilter;
    private final OAuth2LoginSuccessHandler successHandler;
    private final JwtCookieService jwtCookieService;

    public SecurityConfig(JwtCookieAuthenticationFilter jwtCookieAuthenticationFilter,
                          OAuth2LoginSuccessHandler successHandler,
                          JwtCookieService jwtCookieService) {
        this.jwtCookieAuthenticationFilter = jwtCookieAuthenticationFilter;
        this.successHandler = successHandler;
        this.jwtCookieService = jwtCookieService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 인증 상태를 쿠키로만 들고 가므로 서버 세션은 OAuth 핸드셰이크 동안만 쓴다.
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login.html", "/favicon.ico", "/error").permitAll()
                .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                // 그 외 정적 페이지와 모든 API는 인증 필수
                .anyRequest().authenticated())
            .oauth2Login(oauth -> oauth
                .loginPage("/login.html")
                .successHandler(successHandler))
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    jwtCookieService.clear(response);
                    response.sendRedirect(request.getContextPath() + "/login.html");
                }))
            .exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint()))
            // 브라우저 폼이 아니라 fetch 기반이고 SameSite=Lax 쿠키를 쓰므로 CSRF는 끈다.
            .csrf(csrf -> csrf.disable())
            .addFilterBefore(jwtCookieAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * API 요청은 로그인 페이지 HTML(200)이 아니라 401을 받아야 fetch 쪽에서 분기할 수 있다.
     * 위임 순서를 직접 지정해 oauth2Login 이 등록하는 기본 엔트리포인트와의 우선순위 모호함을 없앤다.
     */
    private AuthenticationEntryPoint authenticationEntryPoint() {
        RequestMatcher apiRequests = request -> request.getRequestURI().startsWith("/api/");
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> mappings = new LinkedHashMap<>();
        mappings.put(apiRequests, new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));

        DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(mappings);
        entryPoint.setDefaultEntryPoint(new LoginUrlAuthenticationEntryPoint("/login.html"));
        return entryPoint;
    }
}
