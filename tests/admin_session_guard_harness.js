const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const script = fs.readFileSync(0, 'utf8');

function browser() {
  const calls = [], redirects = [], listeners = {}, timers = new Map();
  let timerId = 0;
  const location = {
    href: 'https://admin.riskraven.ai/users?tab=active#selected',
    origin: 'https://admin.riskraven.ai', pathname: '/users',
    search: '?tab=active', hash: '#selected',
    replace: value => redirects.push(value)
  };
  const context = {
    URL, Request, AbortController, location, navigator: {onLine: true},
    document: {
      visibilityState: 'visible',
      addEventListener: (name, fn) => { listeners[name] = fn; }
    },
    setTimeout: (fn, delay) => { timers.set(++timerId, {fn, delay}); return timerId; },
    clearTimeout: id => timers.delete(id),
    setInterval: (fn, delay) => { assert.equal(delay, 60000); listeners.interval = fn; },
    addEventListener: (name, fn) => { listeners[name] = fn; },
    fetch: (input, init) => new Promise((resolve, reject) => {
      calls.push({input, init, resolve, reject});
      if (init && init.signal) {
        init.signal.addEventListener('abort', () => reject(new Error('aborted')));
      }
    })
  };
  context.window = context;
  vm.runInNewContext(script, context);
  return {context, calls, redirects, listeners, timers};
}

const flush = () => new Promise(resolve => setImmediate(resolve));
const response = (status, url = 'https://admin.riskraven.ai/api/auth/session') => ({status, url});

async function run() {
  const b = browser();
  assert.equal(b.calls.length, 1, 'immediate native probe');
  assert.equal(b.calls[0].input, '/api/auth/session');
  assert.equal(b.calls[0].init.credentials, 'same-origin');
  assert.equal(b.calls[0].init.cache, 'no-store');
  assert.equal([...b.timers.values()][0].delay, 10000);
  for (const name of ['focus', 'online', 'pageshow', 'visibilitychange', 'interval']) b.listeners[name]();
  assert.equal(b.calls.length, 1, 'overlapping events deduplicated');
  b.calls[0].reject(new Error('network failure'));
  await flush();
  assert.equal(b.timers.size, 0);
  for (const status of [200, 403, 500, 503]) {
    b.listeners.interval();
    b.calls.at(-1).resolve(response(status));
    await flush();
    assert.equal(b.redirects.length, 0);
  }
  b.context.navigator.onLine = false;
  const count = b.calls.length;
  b.listeners.interval();
  assert.equal(b.calls.length, count, 'offline probe skipped');
  b.context.navigator.onLine = true;
  b.context.document.visibilityState = 'hidden';
  b.listeners.visibilitychange();
  assert.equal(b.calls.length, count, 'hidden event skipped');
  b.context.document.visibilityState = 'visible';
  for (const name of ['focus', 'online', 'pageshow', 'visibilitychange']) {
    const before = b.calls.length;
    b.listeners[name]({persisted: true});
    assert.equal(b.calls.length, before + 1, name + ' starts probe');
    b.calls.at(-1).resolve(response(200));
    await flush();
  }
  b.listeners.interval();
  const hung = b.calls.at(-1);
  [...b.timers.values()][0].fn();
  await flush();
  assert.equal(hung.init.signal.aborted, true);
  assert.equal(b.redirects.length, 0, 'timeout is not expiry');
  b.listeners.pageshow({persisted: true});
  assert.notEqual(b.calls.at(-1), hung, 'probe recovers after timeout');
  b.calls.at(-1).resolve(response(401));
  await flush();
  assert.deepEqual(b.redirects, ['/login?next=' + encodeURIComponent('/users?tab=active#selected')]);
  b.listeners.focus();
  assert.equal(b.redirects.length, 1);

  for (const [input, status, finalUrl, expires] of [
    ['/api/users', 401, 'https://admin.riskraven.ai/api/users', true],
    [new Request('https://admin.riskraven.ai/api/users'), 401, '', true],
    [new URL('https://admin.riskraven.ai/api/users'), 401, '', true],
    ['https://other.test/api', 401, 'https://other.test/api', false],
    ['https://other.test/api', 401, 'https://admin.riskraven.ai/api', false],
    ['/api/users', 401, 'https://other.test/api', false],
    ['/api/users', 403, 'https://admin.riskraven.ai/api/users', false],
    ['/api/users', 500, 'https://admin.riskraven.ai/api/users', false]
  ]) {
    const c = browser();
    c.calls[0].resolve(response(200));
    await flush();
    const pending = c.context.fetch(input, {method: 'GET'});
    const result = response(status, finalUrl);
    c.calls[1].resolve(result);
    assert.equal(await pending, result, 'wrapper preserves response');
    assert.equal(c.redirects.length, expires ? 1 : 0);
    if (expires) {
      const again = c.context.fetch('/api/another');
      c.calls.at(-1).resolve(response(401));
      await again;
      assert.equal(c.redirects.length, 1, 'only one redirect');
    }
  }
  const c = browser();
  c.calls[0].resolve(response(200));
  await flush();
  const rejected = c.context.fetch('/api/users');
  c.calls.at(-1).reject(new Error('network failure'));
  await assert.rejects(rejected, /network failure/);
  assert.equal(c.redirects.length, 0);
  console.log('Admin session guard behavior checks passed');
}

run().catch(error => { console.error(error); process.exitCode = 1; });
