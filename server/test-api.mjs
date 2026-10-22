// Функциональный прогон API: setup → люди → вход → открыть → отметки → закрыть → отчёт → пароли → rate limit.
// Гоняется против СВЕЖЕГО экземпляра (пустая база)! Запуск: BASE=http://127.0.0.1:18793 node server/test-api.mjs
import assert from 'node:assert/strict';
const BASE = process.env.BASE || 'http://127.0.0.1:8787';
// --- client helper with cookie jar ---
function client(ip = '1.2.3.4') {
  const jar = {};
  return async function (path, body, opts = {}) {
    const headers = { 'X-Real-IP': ip, Cookie: Object.entries(jar).map(([k, v]) => k + '=' + v).join('; ') };
    const init = { method: body === undefined ? 'GET' : 'POST', headers };
    if (body !== undefined) { headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    const res = await fetch(BASE + path, init);
    const sc = res.headers.get('set-cookie');
    if (sc) { const m = sc.match(/^(\w+)=([^;]*);.*Max-Age=(\d+)/); if (m) { if (m[3] === '0') delete jar[m[1]]; else jar[m[1]] = m[2]; } }
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text, headers: res.headers };
  };
}
let r;
const admin = client('10.0.0.1'), s1 = client('10.0.0.2'), s2 = client('10.0.0.3'), s3 = client('10.0.0.4');

// pages
r = await admin('/'); assert.equal(r.status, 200); assert.ok(r.text.includes('אני כאן') && r.text.includes('Я на месте'));
r = await admin('/admin'); assert.equal(r.status, 200); assert.ok(r.text.includes('הגדרה ראשונית'));
r = await admin('/manifest.json'); assert.equal(r.status, 200); assert.ok(r.json.icons.length === 2);
r = await admin('/icon-192.png'); assert.equal(r.status, 200); assert.equal(r.headers.get('content-type'), 'image/png');
r = await admin('/nope'); assert.equal(r.status, 404);

// before setup
r = await s1('/api/state'); assert.equal(r.status, 409); assert.ok(r.json.setup_required);
r = await admin('/api/admin/state'); assert.equal(r.status, 409);
r = await admin('/api/setup', { admin_password: 'abc', shared_password: 'abcd' }); assert.equal(r.status, 400, 'short admin pw rejected');
r = await admin('/api/setup', { admin_password: 'admin123', shared_password: 'plato1' }); assert.equal(r.status, 200);
r = await admin('/api/setup', { admin_password: 'x', shared_password: 'y' }); assert.equal(r.status, 409, 'second setup blocked');
r = await admin('/api/admin/state'); assert.equal(r.status, 200); assert.deepEqual(r.json.users, []); assert.equal(r.json.open, null);

// admin auth
const admin2 = client('10.0.0.9');
r = await admin2('/api/admin/state'); assert.equal(r.status, 401);
r = await admin2('/api/admin/login', { password: 'wrong' }); assert.equal(r.status, 401);
r = await admin2('/api/admin/login', { password: 'admin123' }); assert.equal(r.status, 200);
r = await admin2('/api/admin/state'); assert.equal(r.status, 200);

// users
r = await admin('/api/admin/users/add', { id: '101', name: 'Вася' }); assert.equal(r.status, 200); assert.equal(r.json.users.length, 1);
r = await admin('/api/admin/users/add', { id: '101', name: 'Dup' }); assert.equal(r.status, 409);
r = await admin('/api/admin/users/add', { id: 'bad id', name: 'x' }); assert.equal(r.status, 400);
r = await admin('/api/admin/users/import', { text: '102 Петя Петров\n103, Yossi Cohen\n\n101 Вася Пупкин\nbad id here\n104\tדני לוי' });
assert.equal(r.status, 200); assert.deepEqual(r.json.result, { added: 4, updated: 1, skipped: 0 }, JSON.stringify(r.json.result));
// 'bad id here' -> id 'bad', name 'id here' — valid actually; check count
assert.equal(r.json.users.length, 5);
r = await admin('/api/admin/users/delete', { id: 'bad' }); assert.equal(r.status, 200); assert.equal(r.json.users.length, 4);
r = await admin('/api/admin/users/update', { id: '101', leader: true }); assert.equal(r.status, 200);
assert.ok(r.json.users.find(u => u.id === '101').leader);
r = await admin('/api/admin/users/update', { id: '102', name: 'Пётр' }); assert.equal(r.json.users.find(u => u.id === '102').name, 'Пётр');
r = await admin('/api/admin/users/update', { id: '999', name: 'x' }); assert.equal(r.status, 404);

// soldier login
r = await s1('/api/state'); assert.equal(r.status, 401);
r = await s1('/api/login', { id: '101', password: 'nope' }); assert.equal(r.status, 401);
r = await s1('/api/login', { id: '999', password: 'plato1' }); assert.equal(r.status, 401);
r = await s1('/api/login', { id: '101', password: 'plato1' }); assert.equal(r.status, 200);
r = await s2('/api/login', { id: '102', password: 'plato1' }); assert.equal(r.status, 200);
r = await s3('/api/login', { id: '103', password: 'plato1' }); assert.equal(r.status, 200);
r = await s1('/api/state'); assert.equal(r.status, 200); assert.equal(r.json.me.name, 'Вася Пупкин'); assert.ok(r.json.me.leader); assert.equal(r.json.rollcall, null); assert.equal(r.json.last, null);
const v = r.json.v;
r = await s1('/api/state?v=' + v); assert.equal(r.status, 204, 'unchanged -> 204');
r = await s2('/api/state'); assert.ok(!r.json.me.leader);

// mark while closed
r = await s2('/api/mark', { status: 'present' }); assert.equal(r.status, 409);
// open: non-leader forbidden, leader ok
r = await s2('/api/open', {}); assert.equal(r.status, 403);
r = await s1('/api/open', {}); assert.equal(r.status, 200); assert.ok(r.json.rollcall); assert.equal(r.json.rollcall.opened_by, 'Вася Пупкин');
r = await s1('/api/open', {}); assert.equal(r.status, 409, 'already open');
r = await s2('/api/state?v=' + v); assert.equal(r.status, 200, 'version bumped');
// marks
r = await s2('/api/mark', { status: 'present' }); assert.equal(r.status, 200);
assert.equal(r.json.users.find(u => u.id === '102').status, 'present');
r = await s2('/api/mark', { status: null }); assert.equal(r.json.users.find(u => u.id === '102').status, null);
r = await s2('/api/mark', { status: 'present' }); assert.equal(r.status, 200);
r = await s1('/api/mark', { status: 'present' }); assert.equal(r.status, 200);
// leader sets excused for 103, non-leader cannot
r = await s2('/api/set', { user_id: '103', status: 'excused' }); assert.equal(r.status, 403);
r = await s1('/api/set', { user_id: '103', status: 'excused' }); assert.equal(r.status, 200);
assert.equal(r.json.users.find(u => u.id === '103').status, 'excused');
r = await s1('/api/set', { user_id: 'zzz', status: 'present' }); assert.equal(r.status, 404);
// admin sees counts
r = await admin('/api/admin/state'); assert.deepEqual([r.json.open.present, r.json.open.excused, r.json.open.missing, r.json.open.total], [2, 1, 1, 4]);
// close
r = await s2('/api/close', {}); assert.equal(r.status, 403);
r = await s1('/api/close', {}); assert.equal(r.status, 200); assert.equal(r.json.rollcall, null);
assert.deepEqual(r.json.last.present.sort(), ['Вася Пупкин', 'Пётр']); assert.deepEqual(r.json.last.excused, ['Yossi Cohen']); assert.deepEqual(r.json.last.missing, ['דני לוי']); assert.equal(r.json.last.total, 4);
r = await s1('/api/close', {}); assert.equal(r.status, 409);
r = await admin('/api/admin/state'); assert.equal(r.json.history.length, 1); assert.equal(r.json.open, null);
// admin emergency close
r = await s1('/api/open', {}); assert.equal(r.status, 200);
r = await admin('/api/admin/close', {}); assert.equal(r.status, 200); assert.equal(r.json.open, null); assert.equal(r.json.history.length, 2);
// passwords
r = await admin('/api/admin/password', { kind: 'shared', password: 'newpass' }); assert.equal(r.status, 200);
r = await s1('/api/state'); assert.equal(r.status, 200, 'existing sessions survive password change');
const s4 = client('10.0.0.5');
r = await s4('/api/login', { id: '104', password: 'plato1' }); assert.equal(r.status, 401);
r = await s4('/api/login', { id: '104', password: 'newpass' }); assert.equal(r.status, 200);
r = await admin('/api/admin/logout_all', {}); assert.equal(r.status, 200);
r = await s1('/api/state'); assert.equal(r.status, 401, 'logged out all');
r = await admin('/api/admin/state'); assert.equal(r.status, 200, 'admin session survives logout_all');
r = await admin('/api/admin/password', { kind: 'admin', password: 'adm2' }); assert.equal(r.status, 200);
r = await admin('/api/admin/logout', {}); assert.equal(r.status, 200);
r = await admin('/api/admin/state'); assert.equal(r.status, 401);
r = await admin('/api/admin/login', { password: 'admin123' }); assert.equal(r.status, 401);
r = await admin('/api/admin/login', { password: 'adm2' }); assert.equal(r.status, 200);
// delete user kills session
r = await s4('/api/state'); assert.equal(r.status, 401, 's4 was logged out by logout_all');
r = await s4('/api/login', { id: '104', password: 'newpass' }); assert.equal(r.status, 200);
r = await s4('/api/state'); assert.equal(r.status, 200);
r = await admin('/api/admin/users/delete', { id: '104' }); assert.equal(r.status, 200);
r = await s4('/api/state'); assert.equal(r.status, 401);
// user logout
r = await s1('/api/login', { id: '101', password: 'newpass' }); assert.equal(r.status, 200);
r = await s1('/api/logout', {}); assert.equal(r.status, 200);
r = await s1('/api/state'); assert.equal(r.status, 401);
// case-insensitive id
r = await s1('/api/login', { id: 'yossi', password: 'newpass' }); assert.equal(r.status, 401);
r = await admin('/api/admin/users/add', { id: 'Yossi', name: 'Y' }); assert.equal(r.status, 200);
r = await s1('/api/login', { id: 'yossi', password: 'newpass' }); assert.equal(r.status, 200);
// rate limit
const bad = client('66.6.6.6');
for (let i = 0; i < 30; i++) { r = await bad('/api/login', { id: '101', password: 'x' }); assert.equal(r.status, 401); }
r = await bad('/api/login', { id: '101', password: 'newpass' }); assert.equal(r.status, 429);
// bad content type / method
r = await fetch(BASE + '/api/login', { method: 'POST', body: 'x' }); assert.equal(r.status, 400);
r = await fetch(BASE + '/api/state', { method: 'DELETE' }); assert.equal(r.status, 405);
r = await fetch(BASE + '/healthz'); assert.equal(r.status, 200); assert.equal(await r.text(), 'ok');
console.log('ALL TESTS PASSED');
