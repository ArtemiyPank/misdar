#!/usr/bin/env bash
# Подробная проверка после деплоя. Рабочую базу НЕ трогает: функциональный прогон идёт
# на временном экземпляре приложения с пустой базой на другом порту.
#
#   sudo bash server/test.sh
set -u
DOMAIN="${DOMAIN:-misdar.insafe.top}"
PORT="${PORT:-8793}"
APP=/opt/misdar
DATA=/var/lib/misdar
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE="$APP/node/bin/node"
pass=0; fail=0; warn=0
ok()   { echo "  ✓ $1"; pass=$((pass+1)); }
bad()  { echo "  ✗ $1"; fail=$((fail+1)); }
wrn()  { echo "  ! $1"; warn=$((warn+1)); }
chk()  { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
code() { curl -s -o /dev/null -w '%{http_code}' -m 12 "$@" 2>/dev/null || true; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "== 1. Сервис misdar =="
chk "misdar.service запущен"                 "systemctl is-active --quiet misdar"
chk "включён в автозагрузку"                  "systemctl is-enabled --quiet misdar"
listening_ports() {
  if have ss; then ss -tln 2>/dev/null | awk 'NR>1{print $4}'
  elif have netstat; then netstat -tln 2>/dev/null | awk 'NR>2{print $4}'
  else awk 'NR>1 && $4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | while IFS=: read -r a hp; do printf '%s:%d\n' "$a" "0x$hp"; done | sed 's/^0100007F:/127.0.0.1:/'
  fi
}
chk "слушает только 127.0.0.1:$PORT"          "listening_ports | grep -qx '127.0.0.1:$PORT'"
chk "не слушает на внешних адресах"           "! listening_ports | grep -qE '^(0.0.0.0|\\*|\\[::\\]|00000000|0000.*0000):$PORT\$'"
chk "/healthz отвечает ok"                    "[ \"\$(curl -s -m 5 http://127.0.0.1:$PORT/healthz)\" = ok ]"
chk "/ локально → 200"                        "[ \$(code http://127.0.0.1:$PORT/) = 200 ]"
chk "/admin локально → 200"                   "[ \$(code http://127.0.0.1:$PORT/admin) = 200 ]"
chk "/api/state без входа → 401 или 409"      "code http://127.0.0.1:$PORT/api/state | grep -qE '^(401|409)\$'"
chk "/manifest.json и иконки"                 "[ \$(code http://127.0.0.1:$PORT/manifest.json) = 200 ] && [ \$(code http://127.0.0.1:$PORT/icon-192.png) = 200 ]"
chk "база $DATA/misdar.db существует"         "[ -f $DATA/misdar.db ]"
chk "процесс работает от пользователя misdar" "[ \"\$(ps -o user= -p \$(systemctl show -p MainPID --value misdar) | tr -d ' ')\" = misdar ]"
chk "нет ошибок в журнале за последние 10 мин" "! journalctl -u misdar --since '-10min' --no-pager 2>/dev/null | grep -qiE 'error|unhandled|ECONN|EADDR'"
if systemctl is-active --quiet misdar; then
  mem=$(systemctl show -p MemoryCurrent --value misdar 2>/dev/null); [ -n "$mem" ] && [ "$mem" != "[not set]" ] && echo "  · память: $((mem/1024/1024)) MB"
fi

echo "== 2. Прокси (nginx/caddy) =="
if have nginx; then
  chk "nginx -t"                              "nginx -t"
  chk "nginx активен"                         "systemctl is-active --quiet nginx"
  chk "vhost $DOMAIN в конфиге nginx"         "nginx -T 2>/dev/null | grep -q 'server_name $DOMAIN'"
  chk "vhost проксирует на 127.0.0.1:$PORT"   "nginx -T 2>/dev/null | grep -q 'proxy_pass http://127.0.0.1:$PORT'"
  chk "nginx передаёт X-Real-IP (лимиты per-IP)" "nginx -T 2>/dev/null | grep -q 'proxy_set_header X-Real-IP'"
fi
if have caddy && systemctl is-active --quiet caddy; then
  chk "caddy validate"                        "caddy validate --config /etc/caddy/Caddyfile"
  chk "$DOMAIN в Caddyfile"                   "grep -q '$DOMAIN' /etc/caddy/Caddyfile"
  chk "блок $DOMAIN проксирует на 127.0.0.1:$PORT" "grep -A4 '^$DOMAIN' /etc/caddy/Caddyfile | grep -q 'reverse_proxy 127.0.0.1:$PORT'"
  chk "caddy передаёт X-Real-IP (лимиты per-IP)" "grep -A4 '^$DOMAIN' /etc/caddy/Caddyfile | grep -q 'X-Real-IP'"
fi
chk "через прокси по Host (http, локально) → 200/301" "code -H 'Host: $DOMAIN' http://127.0.0.1/ | grep -qE '^(200|301|308)\$'"

echo "== 3. DNS и HTTPS снаружи =="
resolved=$(getent hosts "$DOMAIN" | awk '{print $1}' | head -1)
if [ -z "$resolved" ]; then bad "DNS: $DOMAIN не резолвится"
elif hostname -I 2>/dev/null | tr ' ' '\n' | grep -qx "$resolved"; then ok "DNS: $DOMAIN → $resolved (этот сервер)"
else wrn "DNS: $DOMAIN → $resolved, среди адресов сервера не найден (NAT? тогда ок)"; fi
chk "http://$DOMAIN → редирект на https (301/308)" "code http://$DOMAIN/ | grep -qE '^(301|308)\$'"
https_ok=0; for _ in 1 2 3 4 5 6; do [ "$(code "https://$DOMAIN/")" = 200 ] && { https_ok=1; break; }; sleep 5; done
if [ "$https_ok" = 1 ]; then ok "https://$DOMAIN/ → 200, сертификат валиден"; else bad "https://$DOMAIN/ не отвечает 200 (сертификат ещё не выпущен? journalctl -u caddy -n 50)"; fi
chk "https://$DOMAIN/admin → 200"              "[ \$(code https://$DOMAIN/admin) = 200 ]"
chk "https://$DOMAIN/api/state → 401/409 (JSON)" "curl -s -m 12 https://$DOMAIN/api/state | grep -qE '\"(error|setup_required)\"'"
if curl -s -I -m 12 "https://$DOMAIN/" | grep -qi 'strict-transport-security'; then ok "HSTS заголовок"
else wrn "HSTS заголовка нет (для Caddy это норма: http→https и так редиректит)"; fi
chk "сертификат действителен ещё > 20 дней"    "openssl s_client -servername $DOMAIN -connect $DOMAIN:443 </dev/null 2>/dev/null | openssl x509 -checkend 1728000 -noout"
if have certbot; then
  if certbot renew --dry-run --cert-name "$DOMAIN" >/dev/null 2>&1; then ok "certbot renew --dry-run (автопродление работает)"; else wrn "certbot renew --dry-run не прошёл (проверь позже: sudo certbot renew --dry-run)"; fi
  if systemctl is-active --quiet certbot.timer 2>/dev/null || systemctl is-active --quiet snap.certbot.renew.timer 2>/dev/null || [ -f /etc/cron.d/certbot ]; then ok "таймер автопродления есть"; else wrn "таймер/cron автопродления certbot не найден"; fi
fi

echo "== 4. Функциональный прогон (временный экземпляр, рабочая база не трогается) =="
if [ -x "$NODE" ] && [ -f "$SRC/server/test-api.mjs" ]; then
  TP=18793; TD=$(mktemp -d)
  PORT=$TP HOST=127.0.0.1 DATA_DIR="$TD" "$NODE" "$APP/app/server.js" >"$TD/log" 2>&1 &
  TPID=$!
  for _ in $(seq 1 20); do sleep 0.3; curl -fsS -m 2 "http://127.0.0.1:$TP/healthz" >/dev/null 2>&1 && break; done
  if BASE="http://127.0.0.1:$TP" "$NODE" "$SRC/server/test-api.mjs" >"$TD/api.log" 2>&1; then ok "94 проверки API: setup, люди, импорт, вход, открыть/закрыть, отметки, статусы, отчёт, пароли, logout, rate-limit"
  else bad "API-прогон упал:"; grep -vE 'Warning|trace-warnings' "$TD/api.log" | head -15 | sed 's/^/      /'; fi
  kill "$TPID" 2>/dev/null; wait "$TPID" 2>/dev/null; rm -rf "$TD"
else
  bad "нет $NODE или $SRC/server/test-api.mjs"
fi

echo "== 5. Существующие сайты не пострадали =="
if [ -f "$DATA/sites-before.txt" ] && [ -s "$DATA/sites-before.txt" ]; then
  while read -r name before_http before_https; do
    [ -z "$name" ] && continue
    now_http="http=$(code "http://$name/")"; now_https="https=$(code "https://$name/")"
    if [ "$now_http" = "$before_http" ] && [ "$now_https" = "$before_https" ]; then ok "$name: без изменений ($before_http $before_https)"
    else bad "$name: было $before_http $before_https, стало $now_http $now_https"; fi
  done < "$DATA/sites-before.txt"
else
  wrn "снимка существующих сайтов нет (не было nginx/caddy server_name до деплоя?)"
fi
if have nginx; then
  others=$(nginx -T 2>/dev/null | grep -cE '^\s*server_name\s' || true)
  echo "  · server_name-блоков в nginx всего: $others"
fi

echo
echo "Итого: ✓ $pass   ✗ $fail   ! $warn"
[ "$fail" = 0 ] && echo "ВСЁ ХОРОШО" || echo "ЕСТЬ ПРОБЛЕМЫ — пришли этот вывод"
exit "$fail"
