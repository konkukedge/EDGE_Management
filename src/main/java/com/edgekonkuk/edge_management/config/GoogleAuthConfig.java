package com.edgekonkuk.edge_management.config;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.auth.oauth2.GoogleCredentials;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
public class GoogleAuthConfig {

    /**
     * 서비스 계정 키의 "내용" 자체. Vercel처럼 시크릿 파일을 올릴 수 없는 환경용.
     * 원본 JSON 문자열 또는 그것을 base64로 인코딩한 값 둘 다 허용한다.
     */
    @Value("${google.service.account.keyJson:}")
    private String serviceAccountKeyJson;

    @Value("${google.service.account.keyPath:}")
    private String serviceAccountKeyPath;

    @Value("${google.oauth.scopes:}")
    private String oauthScopesRaw;

    @Value("${google.drive.scopes:}")
    private String driveScopesRaw;

    @Value("${google.sheets.scopes:}")
    private String sheetsScopesRaw;

    @Bean
    public JsonFactory jsonFactory() {
        return JacksonFactory.getDefaultInstance();
    }

    @Bean
    public HttpTransport httpTransport() throws GeneralSecurityException, IOException {
        return GoogleNetHttpTransport.newTrustedTransport();
    }

    @Bean
    public GoogleCredentials googleCredentials() throws IOException {
        List<String> scopes = new ArrayList<>();
        addScopes(scopes, oauthScopesRaw);
        addScopes(scopes, driveScopesRaw);
        addScopes(scopes, sheetsScopesRaw);

        InputStream keyStream = resolveKeyStream();

        GoogleCredentials base;
        try (InputStream in = keyStream) {
            base = GoogleCredentials.fromStream(in);
        }
        return scopes.isEmpty() ? base : base.createScoped(scopes);
    }

    private void addScopes(List<String> target, String raw) {
        if (raw == null || raw.isBlank()) {
            return;
        }
        target.addAll(Arrays.stream(raw.split(",")).map(String::trim).filter(s -> !s.isBlank()).toList());
    }

    /**
     * 우선순위: 키 내용(환경변수) > 명시 경로 > classpath 기본 위치.
     * 클라우드에서는 첫 번째만 동작하고, 로컬 개발에서는 기존 경로 방식이 그대로 유지된다.
     */
    private InputStream resolveKeyStream() throws IOException {
        InputStream fromContent = keyStreamFromContent();
        if (fromContent != null) {
            return fromContent;
        }

        String resolved = serviceAccountKeyPath;
        if (resolved == null || resolved.isBlank()) {
            resolved = System.getenv("GOOGLE_APPLICATION_CREDENTIALS");
        }
        if (resolved != null && !resolved.isBlank()) {
            if (resolved.startsWith("classpath:")) {
                String cp = resolved.substring("classpath:".length());
                ClassPathResource cpr = new ClassPathResource(cp.startsWith("/") ? cp.substring(1) : cp);
                if (cpr.exists()) {
                    return cpr.getInputStream();
                }
            } else {
                Path p = Paths.get(resolved);
                if (!p.isAbsolute()) {
                    p = Paths.get("").toAbsolutePath().resolve(resolved).normalize();
                }
                if (Files.exists(p)) {
                    return Files.newInputStream(p);
                }
            }
        }

        ClassPathResource cpr = new ClassPathResource("credentials/service-account.json");
        if (cpr.exists()) {
            return cpr.getInputStream();
        }

        throw new IOException(
                "서비스 계정 키를 찾을 수 없습니다. 클라우드 배포 시에는 GOOGLE_SERVICE_ACCOUNT_KEY_JSON 환경변수에 "
                        + "키 JSON(또는 base64 인코딩값)을 넣으세요. 로컬 개발은 GOOGLE_APPLICATION_CREDENTIALS 경로 "
                        + "또는 classpath의 credentials/service-account.json 을 사용합니다.");
    }

    private InputStream keyStreamFromContent() throws IOException {
        String raw = serviceAccountKeyJson;
        if (raw == null || raw.isBlank()) {
            raw = System.getenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON");
        }
        if (raw == null || raw.isBlank()) {
            return null;
        }
        raw = raw.trim();

        // 원본 JSON을 그대로 넣은 경우와 base64로 인코딩한 경우를 모두 받아준다.
        byte[] bytes;
        if (raw.startsWith("{")) {
            bytes = raw.getBytes(StandardCharsets.UTF_8);
        } else {
            try {
                bytes = Base64.getMimeDecoder().decode(raw);
            } catch (IllegalArgumentException e) {
                throw new IOException(
                        "GOOGLE_SERVICE_ACCOUNT_KEY_JSON 값이 JSON도 base64도 아닙니다. 값이 잘렸는지 확인하세요.", e);
            }
        }
        return new ByteArrayInputStream(bytes);
    }
}
