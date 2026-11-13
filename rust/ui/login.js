/* Login form for the HTTP mode, rendered into #secmonk-login with DOM APIs only (no innerHTML). */
(function (global) {
  "use strict";
  const T = global.SecMonkTransport;
  const doc = global.document;
  if (!T || !doc) return;

  function el(tag, cls, text) {
    const e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  let root = null, input, error, button;

  function build() {
    root = doc.getElementById("secmonk-login");
    if (!root) return false;
    const card = el("form", "sm-card rui-login__card");
    card.setAttribute("novalidate", "");
    const body = el("div", "sm-card__body rui-login__body");
    const label = el("label", "rui-login__label", "API key");
    input = el("input", "sm-input rui-login__input");
    input.type = "password";
    input.name = "api_key";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.id = "secmonk-api-key";
    label.htmlFor = input.id;
    error = el("p", "rui-login__error");
    error.setAttribute("role", "alert");
    button = el("button", "sm-btn sm-btn--primary", "Sign in");
    button.type = "submit";
    body.append(el("h1", "rui-login__title", "sec-monk"), label, input, error, button);
    card.append(body);
    root.append(card);
    card.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const key = input.value.trim();
      if (!key) { error.textContent = "Enter an API key."; return; }
      button.disabled = true;
      error.textContent = "";
      try {
        await T.login(key);
        input.value = "";
        global.location.reload();
      } catch (e) {
        error.textContent = e && e.message ? e.message : "Sign-in failed.";
        button.disabled = false;
      }
    });
    return true;
  }

  T.loginUI = {
    show(message) {
      if (doc.readyState === "loading") { doc.addEventListener("DOMContentLoaded", () => T.loginUI.show(message)); return; }
      if (!root && !build()) return;
      error.textContent = message || "";
      root.hidden = false;
      input.focus();
    },
    hide() { if (root) root.hidden = true; },
  };
})(window);
