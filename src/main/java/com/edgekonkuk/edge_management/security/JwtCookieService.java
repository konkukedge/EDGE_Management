package com.edgekonkuk.edge_management.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

/**
 * 로그인 상태를 서버 세션이 아니라 서명된 HttpOnly 쿠키로 유지한다.
 * Vercel 컨테이너는 유휴 시 0으로 축소되고 인스턴스가 여러 개로 흩어지므로
 * 인메모리 세션에 의존하면 사용자가 임의로 로그아웃된다.
 */
@Service
public class JwtCookieService {

    private static final Logger log = LoggerFactory.getLogger(JwtCookieService.class);

    public static final String COOKIE_NAME = "EDGE_SESSION";

    private final byte[] secret;
    private final Duration ttl;
    private final boolean secureCookie;

    public JwtCookieService(@Value("${app.auth.jwt-secret}") String jwtSecret,
                            @Value("${app.auth.session-ttl:PT12H}") Duration ttl,
                            @Value("${app.auth.secure-cookie:true}") boolean secureCookie) {
        byte[] bytes = jwtSecret == null ? new byte[0] : jwtSecret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException(
                    "app.auth.jwt-secret 은 최소 32바이트여야 합니다. APP_JWT_SECRET 환경변수를 확인하세요.");
        }
        this.secret = bytes;
        this.ttl = ttl;
        this.secureCookie = secureCookie;
    }

    public void issue(HttpServletResponse response, String email, String name) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(email)
                    .claim("name", name)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(ttl)))
                    .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            jwt.sign(new MACSigner(secret));
            write(response, jwt.serialize(), (int) ttl.getSeconds());
        } catch (Exception e) {
            throw new IllegalStateException("세션 쿠키 발급에 실패했습니다.", e);
        }
    }

    public void clear(HttpServletResponse response) {
        write(response, "", 0);
    }

    public Optional<String> readSubject(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (!COOKIE_NAME.equals(cookie.getName())) {
                continue;
            }
            return verify(cookie.getValue());
        }
        return Optional.empty();
    }

    private Optional<String> verify(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!jwt.verify(new MACVerifier(secret))) {
                return Optional.empty();
            }
            Date expiry = jwt.getJWTClaimsSet().getExpirationTime();
            if (expiry == null || expiry.toInstant().isBefore(Instant.now())) {
                return Optional.empty();
            }
            return Optional.ofNullable(jwt.getJWTClaimsSet().getSubject());
        } catch (Exception e) {
            log.debug("세션 쿠키 검증 실패", e);
            return Optional.empty();
        }
    }

    private void write(HttpServletResponse response, String value, int maxAgeSeconds) {
        StringBuilder cookie = new StringBuilder()
                .append(COOKIE_NAME).append('=').append(value)
                .append("; Path=/")
                .append("; HttpOnly")
                .append("; SameSite=Lax")
                .append("; Max-Age=").append(maxAgeSeconds);
        if (secureCookie) {
            cookie.append("; Secure");
        }
        response.addHeader("Set-Cookie", cookie.toString());
    }
}
