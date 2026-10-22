#!/usr/bin/env bash
# Разворачивает misdar на этом сервере РЯДОМ с существующими приложениями, не трогая их.
#
# Что делает (всё изолированно):
#   - свой Node в /opt/misdar/node (системный Node не трогается и не ставится)
#   - свой пользователь misdar, данные в /var/lib/misdar
#   - свой systemd-юнит misdar.service, слушает только 127.0.0.1:$PORT
#   - один НОВЫЙ файл vhost в nginx (или блок в Caddyfile) для $DOMAIN; чужие конфиги не редактируются,
#     перед любым изменением делается бэкап, после — nginx -t / caddy validate, при ошибке — откат
#   - сертификат Let's Encrypt через certbot (webroot) для $DOMAIN
# Повторный запуск безопасен (обновление кода).
#
#   sudo bash server/deploy.sh                 # DOMAIN=misdar.insafe.top PORT=8793 по умолчанию
#   sudo CERT_EMAIL=you@mail bash server/deploy.sh   # e-mail для уведомлений Let's Encrypt (необязательно)

set -euo pipefail
DOMAIN="${DOMAIN:-misdar.insafe.top}"
PORT="${PORT:-8793}"
NODE_MAJOR="${NODE_MAJOR:-24}"
CERT_EMAIL="${CERT_EMAIL:-}"
APP=/opt/misdar
DATA=/var/lib/misdar
ACME=/var/www/misdar-acme   # webroot для проверки Let's Encrypt (читает nginx)
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG=/var/log/misdar-deploy.log
STAMP=$(date +%Y%m%d-%H%M%S)

[ "$(id -u)" = 0 ] || { echo "Запускать от root:  sudo bash $0"; exit 1; }
exec > >(tee -a "$LOG") 2>&1
echo "=== deploy $STAMP  domain=$DOMAIN  port=$PORT  src=$SRC ==="

have() { command -v "$1" >/dev/null 2>&1; }
die() { echo; echo "ОШИБКА: $*"; echo "(лог: $LOG)"; exit 1; }

for f in app.js server.js package.json; do [ -f "$SRC/$f" ] || die "нет файла $SRC/$f"; done
have curl || die "нужен curl"
listening_ports() {
  if have ss; then ss -tln 2>/dev/null | awk 'NR>1{print $4}'
  elif have netstat; then netstat -tln 2>/dev/null | awk 'NR>2{print $4}'
  else awk 'NR>1 && $4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | while IFS=: read -r a hp; do printf '%s:%d\n' "$a" "0x$hp"; done
  fi
}

# ── 0. Снимок существующих сайтов — чтобы test.sh мог проверить, что ничего не сломалось ──
mkdir -p "$DATA"
snapshot() {
  local names=""
  if have nginx; then
    names=$(nginx -T 2>/dev/null | grep -E '^\s*server_name\s' | sed -E 's/^\s*server_name\s+//; s/;.*//' | tr ' ' '\n' | grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | sort -u || true)
  fi
  if [ -f /etc/caddy/Caddyfile ]; then
    names="$names $(grep -oE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /etc/caddy/Caddyfile 2>/dev/null | sort -u || true)"
  fi
  for n in $names; do
    [ "$n" = "$DOMAIN" ] && continue
    printf '%s http=%s https=%s\n' "$n" \
      "$(curl -s -o /dev/null -w '%{http_code}' -m 8 "http://$n/" 2>/dev/null || true)" \
      "$(curl -s -o /dev/null -w '%{http_code}' -m 8 "https://$n/" 2>/dev/null || true)"
  done
}
if [ ! -f "$DATA/sites-before.txt" ]; then
  snapshot > "$DATA/sites-before.txt" || true
  echo "Существующие сайты (снимок до деплоя):"; sed 's/^/  /' "$DATA/sites-before.txt"
fi

# ── 1. Какой прокси стоит ──
PROXY=none
if have nginx && systemctl is-active --quiet nginx; then PROXY=nginx
elif have caddy && systemctl is-active --quiet caddy; then PROXY=caddy
fi
echo "Прокси: $PROXY"
[ "$PROXY" != none ] || die "не найден работающий nginx или caddy. Пришли вывод server/inspect.sh — подберу вариант."

# ── 2. Порт ──
if listening_ports | grep -qE "[:.]$PORT\$"; then
  if systemctl is-active --quiet misdar; then echo "Порт $PORT занят нашим же misdar — это обновление"
  else die "порт $PORT занят другим процессом. Запусти с другим: PORT=8794 bash $0"; fi
fi

# ── 3. Пользователь и каталоги ──
id -u misdar >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell "$(command -v nologin || echo /usr/sbin/nologin)" misdar
mkdir -p "$APP/app" "$DATA" "$ACME"
chown -R misdar:misdar "$DATA"
chmod 750 "$DATA"
chmod 755 "$ACME"

# ── 4. Node — изолированный, в /opt/misdar/node ──
ARCH=$(uname -m)
case "$ARCH" in x86_64) NARCH=x64 ;; aarch64|arm64) NARCH=arm64 ;; *) die "неподдерживаемая архитектура $ARCH" ;; esac
NODE="$APP/node/bin/node"
if [ -x "$NODE" ] && [ "$("$NODE" -v | cut -d. -f1)" = "v$NODE_MAJOR" ]; then
  echo "Node уже установлен: $("$NODE" -v)"
else
  echo "Скачиваю Node $NODE_MAJOR.x (linux-$NARCH) в $APP/node ..."
  BASE="https://nodejs.org/dist/latest-v$NODE_MAJOR.x"
  TMP=$(mktemp -d)
  fetch_node() {
    curl -fsSL "$BASE/SHASUMS256.txt" -o "$TMP/SHASUMS256.txt" || return 1
    TAR=$(grep -oE "node-v[0-9.]+-linux-$NARCH\.tar\.xz" "$TMP/SHASUMS256.txt" | head -1)
    [ -n "$TAR" ] || return 1
    curl -fsSL "$BASE/$TAR" -o "$TMP/$TAR" || return 1
    (cd "$TMP" && grep " $TAR\$" SHASUMS256.txt | sha256sum -c - >/dev/null) || { echo "контрольная сумма Node не сошлась"; return 1; }
    rm -rf "$APP/node.new"; mkdir -p "$APP/node.new"
    tar -xJf "$TMP/$TAR" -C "$APP/node.new" --strip-components=1 || return 1
    rm -rf "$APP/node"; mv "$APP/node.new" "$APP/node"
  }
  if fetch_node; then
    echo "Node установлен: $("$NODE" -v)"
  else
    # запасной вариант: системный Node, если он достаточно свежий (node:sqlite есть с 22.13)
    SYS_NODE=$(command -v node || true)
    if [ -n "$SYS_NODE" ] && "$SYS_NODE" -e 'import("node:sqlite").then(()=>process.exit(0),()=>process.exit(1))' 2>/dev/null; then
      echo "Не удалось скачать Node с nodejs.org — использую системный $SYS_NODE ($("$SYS_NODE" -v)) через символическую ссылку"
      rm -rf "$APP/node"; mkdir -p "$APP/node/bin"; ln -s "$SYS_NODE" "$APP/node/bin/node"
    else
      die "не удалось скачать Node с nodejs.org, а системный Node не подходит (нужен ≥ 22.13)"
    fi
  fi
  rm -rf "$TMP"
fi
"$NODE" -e 'import("node:sqlite").then(()=>process.exit(0),()=>process.exit(1))' || die "в этом Node нет node:sqlite"

# ── 5. Код ──
install -m 644 -o root -g root "$SRC/app.js" "$SRC/server.js" "$SRC/package.json" "$APP/app/"
echo "Код скопирован в $APP/app"

# ── 6. systemd ──
cat > /etc/systemd/system/misdar.service <<EOF
[Unit]
Description=Misdar — учёт присутствия на построении
After=network.target

[Service]
Type=simple
User=misdar
Group=misdar
WorkingDirectory=$APP/app
Environment=NODE_ENV=production
Environment=PORT=$PORT
Environment=HOST=127.0.0.1
Environment=DATA_DIR=$DATA
ExecStart=$NODE $APP/app/server.js
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA
LimitNOFILE=16384

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable misdar >/dev/null 2>&1 || true
systemctl restart misdar
for _ in $(seq 1 30); do sleep 0.5; curl -fsS -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; done
if ! curl -fsS -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
  journalctl -u misdar -n 30 --no-pager || true
  die "misdar не поднялся (см. выше journalctl)"
fi
echo "misdar работает на 127.0.0.1:$PORT"

# ── 7. Прокси + TLS ──
if [ "$PROXY" = nginx ]; then
  if [ -d /etc/nginx/sites-enabled ]; then
    CONF="/etc/nginx/sites-available/$DOMAIN.conf"; LINK="/etc/nginx/sites-enabled/$DOMAIN.conf"
  else
    CONF="/etc/nginx/conf.d/$DOMAIN.conf"; LINK=""
  fi
  BACKUP=""
  if [ -f "$CONF" ]; then BACKUP="$CONF.bak-$STAMP"; cp -a "$CONF" "$BACKUP"; echo "Бэкап vhost: $BACKUP"; fi

  write_vhost() {   # $1 = http | https
    {
      echo "# misdar — создано server/deploy.sh $STAMP. Правки — только в этом файле."
      echo "server {"
      echo "    listen 80;"
      echo "    server_name $DOMAIN;"
      echo "    location /.well-known/acme-challenge/ { root $ACME; }"
      if [ "$1" = https ]; then
        echo "    location / { return 301 https://\$host\$request_uri; }"
        echo "}"
        echo "server {"
        echo "    listen 443 ssl;"
        echo "    http2 on;"
        echo "    server_name $DOMAIN;"
        echo "    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;"
        echo "    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;"
        echo "    add_header Strict-Transport-Security \"max-age=15552000\" always;"
      fi
      echo "    client_max_body_size 1m;"
      echo "    location / {"
      echo "        proxy_pass http://127.0.0.1:$PORT;"
      echo "        proxy_http_version 1.1;"
      echo "        proxy_set_header Host \$host;"
      echo "        proxy_set_header X-Real-IP \$remote_addr;"
      echo "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;"
      echo "        proxy_set_header X-Forwarded-Proto \$scheme;"
      echo "        proxy_read_timeout 30s;"
      echo "    }"
      echo "}"
    } > "$CONF"
    if [ -n "$LINK" ]; then ln -sfn "$CONF" "$LINK"; fi
    return 0
  }
  rollback_vhost() {
    echo "nginx -t не прошёл — откатываю наш vhost"
    [ -n "$LINK" ] && rm -f "$LINK"
    rm -f "$CONF"
    [ -n "$BACKUP" ] && mv "$BACKUP" "$CONF" && { [ -n "$LINK" ] && ln -sfn "$CONF" "$LINK"; }
    nginx -t && systemctl reload nginx
    die "vhost откачен, существующие сайты не тронуты"
  }
  apply_nginx() {
    if nginx -t 2>&1 | tail -1 | grep -q successful; then systemctl reload nginx; echo "nginx: vhost $DOMAIN применён ($1)"; else nginx -t || true; rollback_vhost; fi
  }

  # 7a. http2 on; поддерживается nginx >= 1.25.1 — для старых версий используем старый синтаксис
  NGX_VER=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  http2_fix() {
    if [ -n "$NGX_VER" ] && [ "$(printf '%s\n' "1.25.1" "$NGX_VER" | sort -V | head -1)" != "1.25.1" ]; then
      sed -i 's/^    listen 443 ssl;$/    listen 443 ssl http2;/; /^    http2 on;$/d' "$CONF"
    fi
  }

  if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    write_vhost https; http2_fix; apply_nginx https
  else
    write_vhost http; apply_nginx http
    # 7b. сертификат через webroot (не даём certbot самому править конфиги nginx)
    if ! have certbot && have apt-get; then
      echo "certbot не найден — ставлю пакет certbot (apt)"
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q certbot >/dev/null 2>&1 || echo "не удалось поставить certbot через apt"
    fi
    if have certbot; then
      echo "Выпускаю сертификат для $DOMAIN ..."
      # shellcheck disable=SC2086
      if certbot certonly --webroot -w "$ACME" -d "$DOMAIN" -n --agree-tos --keep-until-expiring \
           ${CERT_EMAIL:+-m "$CERT_EMAIL"} ${CERT_EMAIL:---register-unsafely-without-email} \
           --deploy-hook "systemctl reload nginx"; then
        write_vhost https; http2_fix; apply_nginx https
      else
        echo "ВНИМАНИЕ: certbot не выпустил сертификат (DNS ещё не обновился? порт 80 закрыт?). Сайт пока работает по http://$DOMAIN"
        echo "Повтори позже:  sudo bash $0"
      fi
    else
      echo "ВНИМАНИЕ: certbot недоступен — сайт работает по http://$DOMAIN без TLS"
    fi
  fi

elif [ "$PROXY" = caddy ]; then
  CF=/etc/caddy/Caddyfile
  if grep -qE "^\s*$DOMAIN\b" "$CF"; then
    echo "Caddyfile уже содержит $DOMAIN — не трогаю"
  else
    cp -a "$CF" "$CF.bak-$STAMP"; echo "Бэкап Caddyfile: $CF.bak-$STAMP"
    {
      printf '\n# misdar — добавлено server/deploy.sh %s. Правки — только в этом блоке.\n' "$STAMP"
      printf '%s {\n' "$DOMAIN"
      printf '\treverse_proxy 127.0.0.1:%s {\n\t\theader_up X-Real-IP {remote_host}\n\t}\n' "$PORT"
      printf '}\n'
    } >> "$CF"
    if caddy validate --config "$CF" >/dev/null 2>&1; then
      systemctl reload caddy; echo "caddy: блок $DOMAIN добавлен, конфиг перечитан (существующие сайты не прерывались)"
    else
      caddy validate --config "$CF" 2>&1 | tail -5 || true
      mv "$CF.bak-$STAMP" "$CF"; die "Caddyfile невалиден после добавления — откатил, существующие сайты не тронуты"
    fi
  fi
  echo "Жду, пока Caddy выпустит сертификат для $DOMAIN (обычно 5–30 с) ..."
  TLS_OK=0
  for _ in $(seq 1 40); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "https://$DOMAIN/healthz" 2>/dev/null)" = 200 ]; then TLS_OK=1; break; fi
    sleep 3
  done
  if [ "$TLS_OK" = 1 ]; then echo "HTTPS работает: https://$DOMAIN/"
  else echo "ВНИМАНИЕ: https://$DOMAIN пока не отвечает. Посмотри: journalctl -u caddy -n 50 | grep -i $DOMAIN  (DNS? порт 80/443 снаружи?)"; fi
fi

echo
echo "=== Готово ==="
echo "Сайт:    https://$DOMAIN/        Админка: https://$DOMAIN/admin"
echo "Тесты:   sudo bash $SRC/server/test.sh"
echo "Логи:    journalctl -u misdar -f"
echo "Данные:  $DATA/misdar.db   (бэкап: cp $DATA/misdar.db куда-нибудь)"
