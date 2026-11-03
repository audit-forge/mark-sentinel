const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {script, loginUrl} = JSON.parse(fs.readFileSync(0, 'utf8'));

function browser() {
  const calls = [], redirects = [], listeners = {}, timers = new Map();
  let timerId = 0;
  const location = {
    href: 'https://dashboard.example.test:8443/fleet?tab=active&name=a%20b#page-devices',
    origin: 'https://dashboard.example.test:8443',
    replace: value => redirects.push(value)
  };
  const context = {
    URL, Request, AbortController, location,
    document: {
      hidden: false,
      body: {dataset: {sessionLoginUrl: loginUrl}},
      addEventListener: (name, fn) => { listeners[name] = fn; }
    },
    addEventListener: (name, fn) => { listeners[name] = fn; },
    setInterval: (fn, delay) => {
      assert.equal(delay, 60000);
      listeners.interval = fn;
    },
    setTimeout: (fn, delay) => {
      timers.set(++timerId, {fn, delay});
      return timerId;
    },
    clearTimeout: id => timers.delete(id),
    fetch: function(input, init) {
      assert.equal(this.window, this, 'native fetch remains bound to window');
      return new Promise((resolve, reject) => {
        calls.push({input, init, resolve, reject});
        if (init && init.signal) {
          init.signal.addEventListener('abort', () => reject(new Error('aborted')));
        }
      });
    }
  };
  context.window = context;
  vm.runInNewContext(script, context, {timeout: 1000});
  return {context, calls, redirects, listeners, timers};
}

const flush = () => new Promise(resolve => setImmediate(resolve));
const response = status => ({status});
const expectedLogin = b => loginUrl + encodeURIComponent(b.context.location.href);

async function run() {
  const b = browser();
  assert.equal(b.calls.length, 1, 'initial native probe');
  assert.equal(b.calls[0].input, '/api/auth/me');
  assert.equal(b.calls[0].init.credentials, 'same-origin');
  assert.equal(b.calls[0].init.cache, 'no-store');
  assert.ok(b.calls[0].init.signal instanceof AbortSignal);
  assert.equal(b.timers.size, 1);
  assert.equal([...b.timers.values()][0].delay, 10000);
  for (const name of ['interval', 'focus', 'online', 'pageshow', 'visibilitychange']) {
    b.listeners[name]({persisted: true});
  }
  assert.equal(b.calls.length, 1, 'in-flight probes are deduplicated');
  b.calls[0].reject(new Error('offline'));
  await flush();
  assert.equal(b.redirects.length, 0, 'network failure is not expiry');
  assert.equal(b.timers.size, 0);

  for (const name of ['interval', 'focus', 'online', 'pageshow', 'visibilitychange']) {
    const count = b.calls.length;
    b.listeners[name]({persisted: true});
    assert.equal(b.calls.length, count + 1, name + ' starts a fresh probe');
    assert.equal(b.calls.at(-1).input, '/api/auth/me');
    b.calls.at(-1).resolve(response(200));
    await flush();
    assert.equal(b.timers.size, 0, 'completed probe clears timeout');
  }
  b.context.document.hidden = true;
  const count = b.calls.length;
  b.listeners.visibilitychange();
  assert.equal(b.calls.length, count, 'hidden visibility change does not probe');
  b.context.document.hidden = false;

  for (const status of [403, 500, 502, 503]) {
    b.listeners.interval();
    b.calls.at(-1).resolve(response(status));
    await flush();
    assert.equal(b.redirects.length, 0, status + ' does not log out');
  }
  b.listeners.interval();
  const hung = b.calls.at(-1);
  [...b.timers.values()][0].fn();
  await flush();
  assert.equal(hung.init.signal.aborted, true);
  assert.equal(b.redirects.length, 0, 'timeout does not log out');
  assert.equal(b.timers.size, 0);
  b.listeners.online();
  assert.notEqual(b.calls.at(-1), hung, 'probe recovers after abort');
  b.calls.at(-1).resolve(response(401));
  await flush();
  assert.deepEqual(b.redirects, [expectedLogin(b)], 'probe preserves full URL and fragment');
  const afterRedirect = b.calls.length;
  for (const name of ['interval', 'focus', 'online', 'pageshow', 'visibilitychange']) {
    b.listeners[name]();
  }
  assert.equal(b.calls.length, afterRedirect, 'no probes after redirect');

  const initial = browser();
  initial.calls[0].resolve(response(401));
  await flush();
  assert.deepEqual(initial.redirects, [expectedLogin(initial)], 'initial expiry redirects');

  for (const input of ['/api/devices',
    new Request('https://dashboard.example.test:8443/api/devices'),
    new URL('https://dashboard.example.test:8443/api/devices')]) {
    const c = browser();
    const pending = c.context.fetch(input, {method: 'GET'});
    assert.equal(c.calls[1].input, input);
    assert.equal(c.calls[1].init.method, 'GET');
    const rejected = assert.rejects(pending, /Dashboard session expired/);
    c.calls[1].resolve(response(401));
    await rejected;
    c.calls[0].resolve(response(401));
    await flush();
    const again = c.context.fetch('/api/another');
    const result = response(401);
    c.calls.at(-1).resolve(result);
    assert.equal(await again, result);
    assert.deepEqual(c.redirects, [expectedLogin(c)], 'concurrent 401s redirect only once');
  }

  for (const [input, status] of [
    ['https://other.test/api', 401], ['//other.test/api', 401],
    [new Request('https://other.test/api'), 401],
    ['/api/devices', 200], ['/api/devices', 403], ['/api/devices', 500],
    ['/api/devices', 503]
  ]) {
    const c = browser();
    c.calls[0].resolve(response(200));
    await flush();
    const pending = c.context.fetch(input);
    const result = response(status);
    c.calls.at(-1).resolve(result);
    assert.equal(await pending, result, 'wrapper preserves non-expiry responses');
    assert.equal(c.redirects.length, 0);
  }
  const c = browser();
  c.calls[0].resolve(response(200));
  await flush();
  const pending = c.context.fetch('/api/devices');
  const rejected = assert.rejects(pending, /network failure/);
  c.calls.at(-1).reject(new Error('network failure'));
  await rejected;
  assert.equal(c.redirects.length, 0);
  console.log('Dashboard session guard behavior checks passed');
}

run().catch(error => { console.error(error); process.exitCode = 1; });
