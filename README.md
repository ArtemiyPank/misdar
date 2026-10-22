# Мисдар / Пересчёт

Сайт для отметки присутствия на построении. Без зависимостей: один файл логики, встроенный SQLite.

| Файл | Что это |
|---|---|
| `app.js` | вся логика, API, обе страницы (RU/HE) — общее ядро |
| `server.js` | запуск на обычном Linux-сервере (Node ≥ 22.13), слушает 127.0.0.1 за nginx/caddy |
| `index.js` + `wrangler.jsonc` | альтернатива: запуск на Cloudflare Workers (без своего сервера) |
| `server/inspect.sh` | осмотр сервера перед деплоем, только чтение |
| `server/deploy.sh` | установка рядом с существующими приложениями (изолированно, с бэкапами и откатом) |
| `server/test.sh` + `server/test-api.mjs` | подробная проверка после деплоя |

## Как это работает

- `/` — страница солдат: вход по ID + общему паролю (вход сохраняется на полгода), кнопка «Я на месте», список неотметившихся, обновление каждые 2–3 с, пока пересчёт открыт.
- `/admin` — админка (свой пароль): люди, «главные», смена паролей, импорт списка, история.
- Главный (можно нескольких): открыть/закрыть пересчёт, отметить/снять любого, «по уважительной», скопировать отчёт для WhatsApp.
- Данные: `/var/lib/misdar/misdar.db` (SQLite). Бэкап — просто скопировать файл.

## Деплой на свой сервер (nginx или caddy уже стоит, рядом живут другие приложения)

Всё изолировано: свой Node в `/opt/misdar/node` (системный не трогается), свой пользователь `misdar`,
свой `misdar.service`, один новый vhost-файл для домена. Чужие конфиги не редактируются; перед любым
изменением делается бэкап, после — `nginx -t` / `caddy validate`, при ошибке — откат.

```bash
# 1. Код на сервер (от root)
git clone https://github.com/<user>/misdar.git /opt/misdar-src
#    (если нет git: curl -L https://github.com/<user>/misdar/archive/refs/heads/main.tar.gz | tar xz -C /opt && mv /opt/misdar-main /opt/misdar-src)

# 2. Осмотр — ничего не меняет. Вывод пришли мне перед деплоем
bash /opt/misdar-src/server/inspect.sh

# 3. Деплой (DNS misdar.insafe.top должен уже указывать на сервер)
bash /opt/misdar-src/server/deploy.sh
#    необязательно: CERT_EMAIL=you@mail bash ... (почта для писем Let's Encrypt об истечении)

# 4. Проверка (рабочая база не трогается — функциональный прогон на временной копии)
bash /opt/misdar-src/server/test.sh
```

Потом: открой `https://misdar.insafe.top/admin`, задай пароль админа и общий пароль, добавь людей
(или импорт списка `ID имя` построчно), отметь звёздочкой главных, кинь ссылку и общий пароль в группу.
ID — любой короткий, лучше не полный личный номер. Советуй всем добавить сайт на экран «Домой».

### Обновление

```bash
cd /opt/misdar-src && git pull && bash server/deploy.sh && bash server/test.sh
```

### Полезное

```bash
journalctl -u misdar -f                    # логи
systemctl restart misdar                   # перезапуск
cp /var/lib/misdar/misdar.db ~/misdar-$(date +%F).db   # бэкап
```

Удалить полностью: `systemctl disable --now misdar; rm -rf /opt/misdar /var/lib/misdar /etc/systemd/system/misdar.service /etc/nginx/sites-*/misdar.insafe.top.conf /etc/nginx/conf.d/misdar.insafe.top.conf; systemctl daemon-reload; nginx -t && systemctl reload nginx`.

## Альтернатива: Cloudflare Workers (без сервера)

`index.js` + `wrangler.jsonc` — тот же код через Durable Object (SQLite). Деплой: репозиторий → Cloudflare
Dashboard → Workers → Import a repository → Deploy. Или `npx wrangler deploy` с ноута. Бесплатного лимита
(100k запросов/день) на 40 человек хватает с запасом.

## Локально

```bash
node server.js                 # http://127.0.0.1:8793, база в ./data
BASE=http://127.0.0.1:8793 node server/test-api.mjs   # на ПУСТОЙ базе
```

## Что не сделано (можно добавить потом)

Push-уведомления об открытии пересчёта, автозакрытие по таймеру, защита от «отметься за меня»
(сейчас расчёт на доверие — главный видит список глазами), экспорт истории.
