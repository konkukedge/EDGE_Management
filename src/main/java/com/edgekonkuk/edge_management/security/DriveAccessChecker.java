package com.edgekonkuk.edge_management.security;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * 지정된 드라이브 폴더의 공유 목록을 서비스 계정 권한으로 조회해 인가를 판단한다.
 * 사용자에게 Drive 스코프를 요구하지 않으므로 구글 앱 심사가 필요 없다.
 *
 * 한계: 폴더가 구글 그룹에 공유된 경우 개별 이메일이 목록에 나타나지 않는다.
 * 그런 운영 방식이라면 그룹 멤버십 조회(Admin SDK)가 별도로 필요하다.
 */
@Service
public class DriveAccessChecker {

    private static final Logger log = LoggerFactory.getLogger(DriveAccessChecker.class);

    private static final String PERMISSIONS_URL = "https://www.googleapis.com/drive/v3/files/%s/permissions";

    private final GoogleCredentials credentials;
    private final HttpTransport httpTransport;
    private final JsonFactory jsonFactory;

    /** 이 폴더에 공유된 사람만 사이트를 쓸 수 있다. */
    @Value("${app.auth.drive-folder-id:}")
    private String gateFolderId;

    public DriveAccessChecker(GoogleCredentials credentials,
                              HttpTransport httpTransport,
                              JsonFactory jsonFactory) {
        this.credentials = credentials;
        this.httpTransport = httpTransport;
        this.jsonFactory = jsonFactory;
    }

    public boolean isConfigured() {
        return gateFolderId != null && !gateFolderId.isBlank();
    }

    /**
     * @return 해당 이메일이 게이트 폴더에 직접 공유되어 있으면 true.
     */
    public boolean hasAccess(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        if (!isConfigured()) {
            // 폴더가 지정되지 않았다면 인가 판단 근거가 없다. 열어주지 않는다.
            log.error("app.auth.drive-folder-id 가 비어 있어 모든 로그인을 거부합니다.");
            return false;
        }
        try {
            return sharedEmails().contains(email.trim().toLowerCase(Locale.ROOT));
        } catch (IOException e) {
            // 조회 실패 시 통과시키면 게이트가 무력화된다. 막는 쪽으로 실패한다.
            log.error("드라이브 공유 목록 조회 실패 - 접근을 거부합니다. folderId={}", gateFolderId, e);
            return false;
        }
    }

    private Set<String> sharedEmails() throws IOException {
        HttpRequestFactory factory = httpTransport.createRequestFactory(new HttpCredentialsAdapter(credentials));
        Set<String> emails = new HashSet<>();
        String pageToken = null;

        do {
            StringBuilder sb = new StringBuilder(String.format(PERMISSIONS_URL,
                            URLEncoder.encode(gateFolderId, StandardCharsets.UTF_8)))
                    .append("?fields=nextPageToken,permissions(emailAddress,role,type)")
                    .append("&pageSize=100")
                    .append("&supportsAllDrives=true");
            if (pageToken != null) {
                sb.append("&pageToken=").append(URLEncoder.encode(pageToken, StandardCharsets.UTF_8));
            }

            HttpRequest request = factory.buildGetRequest(new GenericUrl(sb.toString()));
            request.setParser(new JsonObjectParser(jsonFactory));
            HttpResponse response = request.execute();
            JsonObject body = JsonParser.parseString(response.parseAsString()).getAsJsonObject();

            var permissions = body.getAsJsonArray("permissions");
            if (permissions != null) {
                for (var element : permissions) {
                    JsonObject permission = element.getAsJsonObject();
                    // type=anyone(링크 공유)은 사실상 전체 공개이므로 인가 근거로 삼지 않는다.
                    String type = optString(permission, "type");
                    if (!"user".equals(type) && !"group".equals(type)) {
                        continue;
                    }
                    String address = optString(permission, "emailAddress");
                    if (address != null && !address.isBlank()) {
                        emails.add(address.trim().toLowerCase(Locale.ROOT));
                    }
                }
            }
            pageToken = optString(body, "nextPageToken");
        } while (pageToken != null && !pageToken.isBlank());

        return emails;
    }

    private static String optString(JsonObject object, String key) {
        var element = object.get(key);
        return element == null || element.isJsonNull() ? null : element.getAsString();
    }
}
