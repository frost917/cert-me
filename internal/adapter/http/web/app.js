"use strict";

(() => {
  if (window.htmx) {
    window.htmx.config.allowEval = false;
    window.htmx.config.allowScriptTags = false;
    window.htmx.config.includeIndicatorStyles = false;
  }

  const byID = (id) => document.getElementById(id);
  const feedback = byID("feedback");
  let csrfToken = "";
  let settingsETag = "";
  let settingsSnapshot = null;
  let resetToken = "";
  let installationStage = "";

  function showMessage(message) {
    feedback.textContent = message || "";
  }

  function showPanel(id) {
    for (const panel of ["setup-panel", "login-panel", "dashboard-panel", "reset-panel"]) {
      byID(panel).hidden = panel !== id;
    }
    byID("logout-button").hidden = id !== "dashboard-panel";
  }

  async function responseMessage(response) {
    try {
      const body = await response.json();
      return body.error?.message || "요청을 처리하지 못했습니다.";
    } catch (_error) {
      return "요청을 처리하지 못했습니다.";
    }
  }

  async function issueCSRF(mode) {
    const path = mode ? `/api/v1/auth/csrf?mode=${encodeURIComponent(mode)}` : "/api/v1/auth/csrf";
    const response = await fetch(path, { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!response.ok) throw new Error(await responseMessage(response));
    const body = await response.json();
    csrfToken = body.data.csrf_token;
  }

  function requestHeaders(withCSRF) {
    const headers = { Accept: "application/json" };
    if (withCSRF) headers["X-CSRF-Token"] = csrfToken;
    return headers;
  }

  async function sendJSON(path, method, payload, withCSRF, etag) {
    const headers = requestHeaders(withCSRF);
    headers["Content-Type"] = "application/json";
    if (etag) headers["If-Match"] = etag;
    const response = await fetch(path, {
      method,
      headers,
      body: JSON.stringify(payload),
      cache: "no-store",
    });
    if (!response.ok) throw new Error(await responseMessage(response));
    return response;
  }

  function fillSettings(settings) {
    const form = byID("settings-form");
    form.elements.service_url.value = settings.service_url;
    for (const key of ["leaf", "root", "intermediate"]) {
      const field = settings[`${key}_validity`];
      form.elements[`${key}_validity_value`].value = field.value;
      form.elements[`${key}_validity_unit`].value = field.unit;
    }
    for (const key of ["rotate_every", "private_delivery_seconds", "public_link_seconds", "crl_interval_seconds", "crl_validity_seconds", "audit_retention_days"]) {
      form.elements[key].value = settings[key];
    }
  }

  async function loadSettings() {
    const notice = byID("settings-unavailable");
    const form = byID("settings-form");
    const response = await fetch("/api/v1/settings", { headers: requestHeaders(false), cache: "no-store" });
    if (!response.ok) {
      form.hidden = true;
      byID("setup-complete-panel").hidden = true;
      notice.hidden = false;
      if (response.status === 409) {
        notice.textContent = "서비스 설정이 아직 생성되지 않았습니다. 최초 service_url 입력 경로는 PR에서 결정할 예정입니다.";
        return;
      }
      throw new Error(await responseMessage(response));
    }
    const body = await response.json();
    settingsSnapshot = body.data;
    settingsETag = response.headers.get("ETag") || "";
    fillSettings(settingsSnapshot);
    notice.hidden = true;
    form.hidden = false;
    byID("setup-complete-panel").hidden = installationStage !== "pki_required";
  }

  function settingsPatch(current, original) {
    const patch = {};
    if (current.service_url !== original.service_url) patch.service_url = current.service_url;
    for (const key of ["leaf_validity", "root_validity", "intermediate_validity"]) {
      if (current[key].value !== original[key].value || current[key].unit !== original[key].unit) patch[key] = current[key];
    }
    for (const key of ["rotate_every", "private_delivery_seconds", "public_link_seconds", "crl_interval_seconds", "crl_validity_seconds", "audit_retention_days"]) {
      if (current[key] !== original[key]) patch[key] = current[key];
    }
    return patch;
  }

  function currentSettings(form) {
    const number = (name) => Number(form.elements[name].value);
    const validity = (prefix) => ({ value: number(`${prefix}_validity_value`), unit: form.elements[`${prefix}_validity_unit`].value });
    return {
      service_url: form.elements.service_url.value,
      leaf_validity: validity("leaf"),
      root_validity: validity("root"),
      intermediate_validity: validity("intermediate"),
      rotate_every: number("rotate_every"),
      private_delivery_seconds: number("private_delivery_seconds"),
      public_link_seconds: number("public_link_seconds"),
      crl_interval_seconds: number("crl_interval_seconds"),
      crl_validity_seconds: number("crl_validity_seconds"),
      audit_retention_days: number("audit_retention_days"),
    };
  }

  async function showDashboard(session, refreshCSRF) {
    showPanel("dashboard-panel");
    byID("account-label").textContent = `로그인 계정: ${session.account.login_name}`;
    if (refreshCSRF) await issueCSRF("session");
    await loadSettings();
  }

  async function initialize() {
    const resetPage = document.body.dataset.page === "reset";
    if (resetPage) {
      const match = window.location.pathname.match(/^\/reset-password\/([^/]+)$/);
      try { resetToken = match ? decodeURIComponent(match[1]) : ""; } catch (_error) { resetToken = ""; }
      window.history.replaceState(null, "", "/");
      showPanel("reset-panel");
      if (!resetToken) showMessage("재설정 링크에 토큰이 없습니다. 운영자에게 새 링크를 요청하세요.");
      try { await issueCSRF("preauth"); } catch (error) { showMessage(error.message); }
      return;
    }

    const setupResponse = await fetch("/api/v1/setup", { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!setupResponse.ok) throw new Error(await responseMessage(setupResponse));
    const setup = (await setupResponse.json()).data;
    installationStage = setup.setup_stage;
    byID("bootstrap-note").hidden = !setup.bootstrap_https;

    if (setup.setup_stage === "account_required") {
      showPanel("setup-panel");
      await issueCSRF();
      return;
    }

    const sessionResponse = await fetch("/api/v1/auth/me", { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!sessionResponse.ok) {
      if (sessionResponse.status !== 401) throw new Error(await responseMessage(sessionResponse));
      showPanel("login-panel");
      await issueCSRF();
      return;
    }
    await showDashboard((await sessionResponse.json()).data, true);
  }

  byID("admin-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      await sendJSON("/api/v1/setup/admin", "POST", {
        login_name: form.elements.login_name.value,
        password: form.elements.password.value,
      }, true);
      form.reset();
      installationStage = "pki_required";
      showPanel("login-panel");
      showMessage("관리자 계정을 만들었습니다. 로그인하세요.");
      await issueCSRF();
    } catch (error) { showMessage(error.message); }
  });

  byID("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const response = await sendJSON("/api/v1/auth/login", "POST", {
        login_name: form.elements.login_name.value,
        password: form.elements.password.value,
      }, true);
      const body = await response.json();
      csrfToken = body.data.csrf_token;
      form.reset();
      await showDashboard(body.data, false);
      showMessage("");
    } catch (error) { showMessage(error.message); }
  });

  byID("logout-button").addEventListener("click", async () => {
    try {
      const response = await fetch("/api/v1/auth/logout", { method: "POST", headers: requestHeaders(true), cache: "no-store" });
      if (!response.ok) throw new Error(await responseMessage(response));
      csrfToken = "";
      showPanel("login-panel");
      await issueCSRF();
    } catch (error) { showMessage(error.message); }
  });

  byID("reset-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      if (!resetToken) throw new Error("재설정 링크를 다시 열어 주세요.");
      await sendJSON("/api/v1/auth/password-reset", "POST", {
        reset_token: resetToken,
        new_password: form.elements.new_password.value,
      }, true);
      resetToken = "";
      form.reset();
      showPanel("login-panel");
      showMessage("비밀번호를 변경했습니다. 새 비밀번호로 로그인하세요.");
      await issueCSRF();
    } catch (error) { showMessage(error.message); }
  });

  byID("settings-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const patch = settingsPatch(currentSettings(form), settingsSnapshot);
      if (Object.keys(patch).length === 0) {
        byID("settings-result").textContent = "변경된 설정이 없습니다.";
        return;
      }
      const previousServiceURL = settingsSnapshot.service_url;
      const response = await sendJSON("/api/v1/settings", "PATCH", patch, true, settingsETag);
      settingsSnapshot = (await response.json()).data;
      settingsETag = response.headers.get("ETag") || settingsETag;
      fillSettings(settingsSnapshot);
      byID("settings-result").textContent = previousServiceURL === settingsSnapshot.service_url
        ? "설정을 저장했습니다."
        : `서비스 주소를 변경했습니다. 새 주소 ${settingsSnapshot.service_url}로 다시 접속하세요.`;
    } catch (error) { byID("settings-result").textContent = error.message; }
  });

  byID("setup-complete-button").addEventListener("click", async () => {
    try {
      if (!settingsETag) throw new Error("서비스 설정을 먼저 저장하세요.");
      const response = await fetch("/api/v1/setup/complete", {
        method: "POST",
        headers: { ...requestHeaders(true), "If-Match": settingsETag },
        cache: "no-store",
      });
      if (!response.ok) throw new Error(await responseMessage(response));
      const body = await response.json();
      installationStage = body.data.setup_stage;
      byID("setup-complete-panel").hidden = true;
      showMessage("초기 설정을 완료했습니다.");
    } catch (error) { showMessage(error.message); }
  });

  initialize().catch((error) => {
    showMessage(error.message || "서비스를 불러오지 못했습니다.");
  });
})();
