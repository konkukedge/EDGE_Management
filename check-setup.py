"""배포/실행 전 자격증명 점검. 사용법: python check-setup.py"""
import io, json, os, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def load_env(path=".env.local"):
    if not os.path.exists(path):
        return
    for line in io.open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

def main():
    load_env()
    ok = True

    key_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "credentials/service-account.json")
    if not os.path.exists(key_path):
        print("[X] 서비스 계정 키가 없습니다: %s" % key_path)
        return 1
    try:
        key = json.load(io.open(key_path, encoding="utf-8"))
    except Exception as e:
        print("[X] 키 파일이 올바른 JSON 이 아닙니다: %s" % e)
        return 1

    if key.get("type") != "service_account":
        print("[X] 이 파일은 서비스 계정 키가 아닙니다 (type=%s)." % key.get("type"))
        print("    OAuth 클라이언트 JSON 을 받으신 것 같습니다. 서비스 계정 > 키 에서 받으세요.")
        return 1

    sa_email = key.get("client_email", "?")
    print("[O] 서비스 계정 키 정상")
    print("    project : %s" % key.get("project_id"))
    print("    계정     : %s" % sa_email)

    folder = os.environ.get("AUTH_DRIVE_FOLDER_ID", "").strip()
    if not folder:
        print("[!] AUTH_DRIVE_FOLDER_ID 가 비어 있어 폴더 점검을 건너뜁니다.")
        return 0 if ok else 1

    try:
        from google.oauth2 import service_account
        from google.auth.transport.requests import AuthorizedSession
    except ImportError:
        print("[!] google-auth 미설치로 폴더 점검을 건너뜁니다. (pip install google-auth requests)")
        return 0

    creds = service_account.Credentials.from_service_account_file(
        key_path, scopes=["https://www.googleapis.com/auth/drive.readonly"])
    session = AuthorizedSession(creds)

    meta = session.get(
        "https://www.googleapis.com/drive/v3/files/%s" % folder,
        params={"fields": "id,name,mimeType", "supportsAllDrives": "true"})
    if meta.status_code == 404:
        print("[X] 폴더를 찾을 수 없습니다. ID 가 틀렸거나 서비스 계정에 공유되지 않았습니다.")
        print("    이 계정을 폴더 공유에 추가하세요: %s" % sa_email)
        return 1
    if meta.status_code != 200:
        print("[X] 폴더 조회 실패 %s: %s" % (meta.status_code, meta.text[:200]))
        return 1
    print("[O] 폴더 접근 가능: %s" % meta.json().get("name"))

    perms, token = [], None
    while True:
        params = {"fields": "nextPageToken,permissions(emailAddress,role,type)",
                  "pageSize": 100, "supportsAllDrives": "true"}
        if token:
            params["pageToken"] = token
        resp = session.get(
            "https://www.googleapis.com/drive/v3/files/%s/permissions" % folder, params=params)
        if resp.status_code != 200:
            print("[X] 공유 목록 조회 실패 %s: %s" % (resp.status_code, resp.text[:200]))
            print("    서비스 계정 권한이 부족할 수 있습니다(뷰어로는 공유 목록이 안 보일 수 있음).")
            return 1
        body = resp.json()
        perms.extend(body.get("permissions", []))
        token = body.get("nextPageToken")
        if not token:
            break

    users  = [p for p in perms if p.get("type") == "user"]
    groups = [p for p in perms if p.get("type") == "group"]
    anyone = [p for p in perms if p.get("type") == "anyone"]

    print("[O] 공유 목록 %d건 (개인 %d / 그룹 %d / 링크공개 %d)"
          % (len(perms), len(users), len(groups), len(anyone)))
    for p in users[:15]:
        print("      - %s (%s)" % (p.get("emailAddress"), p.get("role")))
    if len(users) > 15:
        print("      ... 외 %d명" % (len(users) - 15))

    if anyone:
        print("[!] '링크가 있는 모든 사용자' 공유가 걸려 있습니다.")
        print("    이 앱은 이를 인가 근거로 쓰지 않지만, 드라이브 자체는 사실상 공개 상태입니다.")
    if groups:
        print("[!] 그룹 공유가 있습니다. 그룹으로만 공유된 사람은 로그인이 거부됩니다:")
        for p in groups:
            print("      - %s" % p.get("emailAddress"))
    if not users:
        print("[X] 개인 공유가 한 명도 없어 아무도 로그인할 수 없습니다.")
        ok = False

    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
