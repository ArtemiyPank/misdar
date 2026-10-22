#!/usr/bin/env bash
# Осмотр сервера перед деплоем. ТОЛЬКО ЧТЕНИЕ — ничего не меняет.
# Запуск:  bash server/inspect.sh        (лучше от root, чтобы видеть все порты и конфиги)
set -u
DOMAIN="${DOMAIN:-misdar.insafe.top}"
PORT="${PORT:-8793}"
hr() { printf '\n== %s ==\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

hr "Система"
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null && echo "OS: ${PRETTY_NAME:-?}"
echo "Kernel: $(uname -r)   Arch: $(uname -m)   $(uptime -p 2>/dev/null)"
echo "CPU: $(nproc) cores   RAM: $(free -m | awk '/Mem:/{print $2" MB total, "$7" MB avail"}')"
echo "Disk /: $(df -h / | awk 'NR==2{print $3" used of "$2" ("$5")"}')"
echo "IPs: $(hostname -I 2>/dev/null)"
echo "Запущено от: $(id -un) (uid $(id -u))"

hr "Кто слушает порты"
listening() {  # адрес:порт  процесс
  if have ss; then ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4"  "$6}' | sed -E 's/users:\(\("([^"]+)".*/\1/' | sort -u
  elif have netstat; then netstat -tlnp 2>/dev/null | tail -n +3 | awk '{print $4"  "$7}' | sort -u
  else awk 'NR>1 && $4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | while IFS=: read -r a hp; do printf '%s:%d\n' "$a" "0x$hp"; done | sort -u
  fi
}
listening | sed 's/^/  /'
if listening | awk '{print $1}' | grep -qE "[:.]$PORT\$"; then echo "Порт $PORT для misdar: ЗАНЯТ"; else echo "Порт $PORT для misdar: свободен"; fi

hr "Сервисы"
for s in nginx caddy apache2 httpd docker traefik haproxy ufw firewalld fail2ban certbot.timer snap.certbot.renew.timer misdar; do
  st=$(systemctl is-active "$s" 2>/dev/null || true)
  [ -n "$st" ] && [ "$st" != "inactive" ] && echo "$s: $st"
done
echo "Запущенные сервисы (без системных):"
systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print "  "$1}' \
  | grep -viE 'systemd|dbus|cron|getty|ssh|rsyslog|polkit|networkd|resolved|journald|udev|logind|unattended|snapd|apparmor|qemu|cloud|chrony|ntp|acpid|irqbalance|multipath|lvm|thermald|console|atd|anacron|ModemManager|accounts|user@|dpkg|packagekit' || true

hr "nginx"
if have nginx; then
  nginx -v 2>&1
  if [ -d /etc/nginx/sites-enabled ]; then echo "Схема: sites-available/sites-enabled"; else echo "Схема: conf.d"; fi
  echo "Файлы:"; ls -1 /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null | sed 's/^/  /'
  echo "server_name / listen (из полного конфига):"
  nginx -T 2>/dev/null | grep -E '^\s*(server_name|listen)\s' | sed -E 's/^\s+//' | sort | uniq -c | sort -rn | head -30 | sed 's/^/  /'
  echo "nginx -t: $(nginx -t 2>&1 | tail -1)"
else echo "нет"; fi

hr "caddy"
if have caddy; then
  caddy version 2>/dev/null
  echo "Caddyfile (без комментариев):"; grep -vE '^\s*(#|$)' /etc/caddy/Caddyfile 2>/dev/null | head -40 | sed 's/^/  /'
else echo "нет"; fi

hr "apache"
if have apache2; then apache2 -v 2>/dev/null | head -1; elif have httpd; then httpd -v 2>/dev/null | head -1; else echo "нет"; fi

hr "docker"
if have docker; then docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null | head -20 || echo "docker есть, но демон не отвечает"; else echo "нет"; fi

hr "Инструменты"
for t in node npm git curl certbot python3 sqlite3; do
  if have "$t"; then printf '  %-8s %s\n' "$t" "$("$t" --version 2>&1 | head -1 | cut -c1-60)"; else printf '  %-8s нет\n' "$t"; fi
done
have openssl && printf '  %-8s %s\n' openssl "$(openssl version 2>/dev/null)"
if [ -x /opt/misdar/node/bin/node ]; then echo "  Node misdar: $(/opt/misdar/node/bin/node -v)"; fi

hr "TLS / Let's Encrypt"
if [ -d /etc/letsencrypt/live ]; then ls -1 /etc/letsencrypt/live | grep -v README | sed 's/^/  /'; else echo "сертификатов certbot нет"; fi
[ -d /var/lib/caddy/.local/share/caddy/certificates ] && echo "caddy хранит свои сертификаты" || true

hr "Firewall"
if have ufw; then ufw status 2>/dev/null | head -15; fi
if have firewall-cmd; then firewall-cmd --list-all 2>/dev/null | head -15; fi
if have iptables; then echo "iptables INPUT правил: $(iptables -S INPUT 2>/dev/null | wc -l)"; fi

hr "DNS"
echo "$DOMAIN -> $(getent hosts "$DOMAIN" | awk '{print $1}' | paste -sd, 2>/dev/null || echo 'не резолвится')"

hr "Следы misdar"
ls -ld /opt/misdar /var/lib/misdar /etc/systemd/system/misdar.service 2>/dev/null || echo "нет (чистая установка)"

hr "Процессы (топ по памяти)"
ps -eo user,pid,etime,rss,cmd --sort=-rss 2>/dev/null | grep -vE 'ps -eo|\]$|grep' | head -12 | cut -c1-150

echo
echo "Готово. Ничего не менялось."
