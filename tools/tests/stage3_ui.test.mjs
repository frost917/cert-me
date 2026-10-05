// Browser-free behavior tests of the actual embedded script. Run with Node:
// node tools/tests/stage3_ui.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";

const script = await readFile(new URL("../../internal/adapter/http/web/app.js", import.meta.url), "utf8");
const settings = {
  service_url: "https://cert.example",
  leaf_validity: { value: 1, unit: "years" },
  root_validity: { value: 20, unit: "years" },
  intermediate_validity: { value: 10, unit: "years" },
  rotate_every: 3, private_delivery_seconds: 10800, public_link_seconds: 600,
  crl_interval_seconds: 43200, crl_validity_seconds: 172800, audit_retention_days: 365,
};
const response = (status, data, headers = {}) => ({
  ok: status >= 200 && status < 300, status,
  json: async () => data,
  headers: { get: name => headers[name] || null },
});
const settle = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };

function browserFixture({ reset = false, exists = false, failCreate = false, loseCreate = false } = {}) {
  const nodes = new Map();
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, { hidden: true, textContent: "", value: "", events: {}, elements: {},
      addEventListener(type, handler) { this.events[type] = handler; }, reset() {} });
    return nodes.get(id);
  };
  const form = node("settings-form");
  for (const [name, value] of Object.entries(settings)) {
    if (name.endsWith("_validity")) {
      form.elements[`${name}_value`] = { value: String(value.value) };
      form.elements[`${name}_unit`] = { value: value.unit };
    } else form.elements[name] = { value: String(value) };
  }
  const calls = [];
  const history = [];
  const fetch = async (url, options = {}) => {
    calls.push({ url, ...options });
    if (url === "/api/v1/setup") return response(200, { data: { setup_stage: "pki_required", bootstrap_https: true } });
    if (url === "/api/v1/auth/me") return response(200, { data: { account: { login_name: "operator" } } });
    if (url.startsWith("/api/v1/auth/csrf")) return response(200, { data: { csrf_token: "unit-test-csrf" } });
	    if (url === "/api/v1/setup/settings") {
      if (failCreate) return response(422, { error: { code: "invalid_service_url", message: "Invalid service address." } });
      exists = true;
      if (loseCreate) throw new TypeError("Disposable test connection interrupted.");
      return response(201, { data: { ...settings, version: 1 } }, { ETag: '"v1"' });
    }
    if (url === "/api/v1/settings" && options.method === "PATCH") {
      return response(200, { data: { ...settings, rotate_every: 4, version: 2 } }, { ETag: '"v2"' });
    }
    if (url === "/api/v1/settings") return exists
      ? response(200, { data: { ...settings, version: 1 } }, { ETag: '"v1"' })
      : response(409, { error: { code: "settings_not_configured", message: "Settings missing." } });
    throw new Error(`Unexpected test route: ${url}`);
  };
  const window = { location: { pathname: reset ? "/reset-password/disposable-test-token" : "/" },
    history: { replaceState: (_state, _title, url) => history.push(url) },
    htmx: { config: {} } };
  runInNewContext(script, { window, document: { body: { dataset: { page: reset ? "reset" : "app" } }, getElementById: node }, fetch, console, TypeError });
  return { node, calls, history, window, form };
}

export async function verifyStage3UI() {
  const initial = browserFixture();
  await settle();
  assert.equal(initial.form.hidden, false, "a new authenticated installation must show the settings input form");
  assert.equal(initial.node("setup-complete-panel").hidden, true, "completion stays hidden until settings exist");
  await initial.form.events.submit({ preventDefault() {}, currentTarget: initial.form });
  const creation = initial.calls.find(call => call.url === "/api/v1/setup/settings");
  assert.ok(creation, "initial submit must call the approved creation API");
  assert.equal(creation.method, "POST");
  assert.equal(creation.headers["X-CSRF-Token"], "unit-test-csrf");
  assert.equal(creation.headers["If-Match"], undefined);
  assert.deepEqual(JSON.parse(creation.body), settings);
  assert.equal(initial.node("setup-complete-panel").hidden, false);
  initial.form.elements.rotate_every.value = "4";
  await initial.form.events.submit({ preventDefault() {}, currentTarget: initial.form });
  const patch = initial.calls.find(call => call.method === "PATCH");
  assert.equal(patch.headers["If-Match"], '"v1"');
  assert.deepEqual(JSON.parse(patch.body), { rotate_every: 4 });

  const failed = browserFixture({ failCreate: true });
  await settle();
  await failed.form.events.submit({ preventDefault() {}, currentTarget: failed.form });
  assert.equal(failed.node("setup-complete-panel").hidden, true);
  assert.equal(failed.node("settings-result").textContent, "Invalid service address.");

  const lost = browserFixture({ loseCreate: true });
  await settle();
  await lost.form.events.submit({ preventDefault() {}, currentTarget: lost.form });
  assert.equal(lost.node("setup-complete-panel").hidden, false, "lost creation response must recover the committed settings through GET");
  assert.equal(lost.calls.filter(call => call.url === "/api/v1/setup/settings").length, 1);
  lost.form.elements.rotate_every.value = "4";
  await lost.form.events.submit({ preventDefault() {}, currentTarget: lost.form });
  assert.ok(lost.calls.some(call => call.method === "PATCH" && call.headers["If-Match"] === '"v1"'));

  const reset = browserFixture({ reset: true });
  await settle();
  assert.deepEqual(reset.history, ["/"]);
  assert.equal(reset.node("reset-panel").hidden, false);
  assert.ok(reset.calls.some(call => call.url === "/api/v1/auth/csrf?mode=preauth"));
  assert.equal(reset.window.htmx.config.allowEval, false);
  assert.equal(reset.window.htmx.config.allowScriptTags, false);
  console.log("PASS stage3 UI: initial creation, subsequent PATCH, rejected creation, reset history and pre-auth mode");
}

await verifyStage3UI();
