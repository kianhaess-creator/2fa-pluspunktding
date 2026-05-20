const store = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (entry.expiresAt < now) store.delete(key);
  }
}, 60_000);

function get(key) {
  const entry = store.get(key);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) { store.delete(key); return null; }
  return entry.value;
}

function set(key, value, ttlSeconds) {
  store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
}

function del(...keys) {
  keys.forEach(k => store.delete(k));
}

function incr(key) {
  const current = get(key);
  const next = (current === null ? 0 : parseInt(current)) + 1;
  const existing = store.get(key);
  const ttlSeconds = existing ? Math.ceil((existing.expiresAt - Date.now()) / 1000) : 900;
  set(key, String(next), ttlSeconds);
  return next;
}

function expire(key, ttlSeconds) {
  const entry = store.get(key);
  if (entry) entry.expiresAt = Date.now() + ttlSeconds * 1000;
}

function ttl(key) {
  const entry = store.get(key);
  if (!entry) return -2;
  return Math.ceil((entry.expiresAt - Date.now()) / 1000);
}

module.exports = { get, set, del, incr, expire, ttl };
