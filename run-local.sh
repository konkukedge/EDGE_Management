#!/usr/bin/env bash
# 로컬 개발 서버 실행. .env.local 의 값을 읽어 부팅한다.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env.local ]; then
  echo "[!] .env.local 이 없습니다. .env.example 을 복사해 값을 채우세요." >&2
  exit 1
fi

set -a; . ./.env.local; set +a

missing=()
for var in GOOGLE_OAUTH_CLIENT_ID GOOGLE_OAUTH_CLIENT_SECRET AUTH_DRIVE_FOLDER_ID APP_JWT_SECRET; do
  [ -n "${!var:-}" ] || missing+=("$var")
done
if [ ${#missing[@]} -gt 0 ]; then
  echo "[!] .env.local 에 다음 값이 비어 있습니다:" >&2
  printf '      - %s\n' "${missing[@]}" >&2
  exit 1
fi

key="${GOOGLE_APPLICATION_CREDENTIALS:-credentials/service-account.json}"
if [ -z "${GOOGLE_SERVICE_ACCOUNT_KEY_JSON:-}" ] && [ ! -f "$key" ]; then
  echo "[!] 서비스 계정 키 파일이 없습니다: $key" >&2
  exit 1
fi

# 시스템 기본 JVM 이 Java 8 이면 Gradle 이 돌지 않는다. 21 이상을 찾아 쓴다.
if [ -z "${JAVA_HOME:-}" ] || ! "${JAVA_HOME}/bin/java" -version 2>&1 | grep -qE '"(2[1-9]|[3-9][0-9])'; then
  for candidate in "/c/Program Files/Android/Android Studio/jbr" "$HOME/.jdks"/*; do
    if [ -x "$candidate/bin/java" ] && "$candidate/bin/java" -version 2>&1 | grep -qE '"(2[1-9]|[3-9][0-9])'; then
      export JAVA_HOME="$candidate"; break
    fi
  done
fi
[ -n "${JAVA_HOME:-}" ] || { echo "[!] JDK 21 이상을 찾지 못했습니다." >&2; exit 1; }
echo "[i] JAVA_HOME=$JAVA_HOME"

./gradlew --no-daemon bootRun
