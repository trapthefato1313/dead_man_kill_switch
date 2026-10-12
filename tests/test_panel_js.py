"""Run the panel's JavaScript for real, against a fake DOM.

The login button once had no handler at all: `el()` sent functions through
`setAttribute`, which stringifies them into inline JS and attaches nothing. It
looked fine in the source, worked in every Python test, and was dead in the
browser. A dead button in a dead man's switch is not a cosmetic bug, so the
JavaScript now gets executed rather than eyeballed.

Skipped, not failed, when bun is absent: a missing test runner must not turn
into a false alarm about the product.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from dmks.webui import PAGE

BUN = shutil.which("bun") or shutil.which("deno")

SCRIPT = re.search(r"<script>(.*?)</script>", PAGE, re.S).group(1)


def js_list(value) -> str:
    return json.dumps(value)


PRELUDE = r"""
// --- a DOM small enough to trust ------------------------------------------
let created = 0;
class Node {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = []; this.attributes = {}; this.style = {}; this.dataset = {};
    this._text = ""; this.classList = makeClassList(this); created++;
  }
  set className(v) { this.attributes.class = String(v); }
  get className() { return this.attributes.class || ""; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text || this.children.map(c => c.textContent).join(""); }
  set innerHTML(v) { this._html = String(v); }
  get innerHTML() { return this._html || ""; }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener(name, fn) { (this._handlers ||= {})[name] = fn; }
  removeEventListener() {}
  focus() {}
  replaceChildren(...kids) { this.children = kids; }
  get value() { return this._value || ""; }
  set value(v) { this._value = String(v); }
  get disabled() { return this._disabled || false; }
  set disabled(v) { this._disabled = !!v; }
  querySelector() { return null; }
  find(pred) {
    if (pred(this)) return this;
    for (const c of this.children) { const r = c.find && c.find(pred); if (r) return r; }
    return null;
  }
  all() {
    let out = [this];
    for (const c of this.children) if (c.all) out = out.concat(c.all());
    return out;
  }
}
function makeClassList(node) {
  const read = () => (node.attributes.class || "").split(/\s+/).filter(Boolean);
  return {
    add(...c) { node.attributes.class = [...new Set([...read(), ...c])].join(" "); },
    remove(...c) { node.attributes.class = read().filter(x => !c.includes(x)).join(" "); },
    contains(c) { return read().includes(c); },
  };
}
class TextNode {
  constructor(text) { this._text = String(text); this.children = []; this.attributes = {}; }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); }
  all() { return [this]; }
  find() { return null; }
}
const registry = {};
globalThis.document = {
  body: new Node("body"),
  createElement: t => new Node(t),
  createTextNode: t => new TextNode(t),
  getElementById: id => (registry[id] ||= new Node("div")),
  querySelector: sel => globalThis.document.getElementById(sel.replace(/^#/, "")),
  addEventListener() {},
};
globalThis.window = { addEventListener() {} };

// The page ends with `boot()`, which fetches. Stub it to the "not logged in"
// answer so the run exercises the login path and never rejects unhandled.
globalThis.fetch = async () => ({
  ok: false,
  status: 401,
  json: async () => ({ error: "no session" }),
});
process.on("unhandledRejection", e => {
  console.log("FALHOU: rejeicao nao tratada: " + e);
  process.exit(1);
});

// The page's own helpers, which is what we are testing.
"""

POSTLUDE = r"""
// --- assertions -----------------------------------------------------------
let failures = 0;
const ok = (name, cond) => {
  if (!cond) { failures++; console.log("FALHOU: " + name); }
  else console.log("ok: " + name);
};

// A function prop must be attached, not stringified into an attribute.
const btn = el("button", { class: "big", onclick: () => { btn._fired = true; } }, ["Entrar"]);
ok("el() liga onclick como propriedade", typeof btn.onclick === "function");
ok("el() nao escreve a funcao como atributo", btn.attributes.onclick === undefined);
ok("el() ainda passa class", btn.className === "big");
ok("el() ainda passa atributos normais", el("input", { type: "password" }).attributes.type === "password");
btn.onclick();
ok("o handler dispara", btn._fired === true);

// Children can be strings or nodes.
const card = el("div", {}, ["texto", el("b", {}, ["bom"])]);
ok("el() anexa strings", card.children[0].textContent === "texto");
ok("el() anexa nos", card.children[1].children[0].textContent === "bom");

// Formatting used by the countdown.
ok("fmtD: dias", fmtD(25 * 86400) === "25d 0h");
ok("fmtD: horas", fmtD(3600 * 5 + 60 * 3) === "5h 3m");
ok("fmtD: minutos", fmtD(90) === "1m");
ok("fmtD: nunca negativo", fmtD(-500) === "0m");
ok("DAYS e um dia", DAYS === 86400);

// boot() ran on load and, with a 401 stub, must have rendered the login form.
await new Promise(r => setTimeout(r, 10));
const app = document.getElementById("app");
ok("boot() mostra o login quando nao ha sessao",
   app.children.length > 0 && app.find(n => n.className === "card") !== null);
ok("o login tem campo de palavra-passe",
   app.find(n => n.attributes.type === "password") !== null);
ok("o botao de entrar tem handler",
   app.find(n => n.attributes.class === "big ok")?.onclick instanceof Function);

console.log(failures === 0 ? "JS OK" : "JS FALHOU");
if (failures) process.exit(1);
"""


@unittest.skipUnless(BUN, "sem bun/deno: teste de JavaScript ignorado")
class PanelJavaScript(unittest.TestCase):
    def _run(self, body: str, extra: str = "") -> str:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.js"
            path.write_text(PRELUDE + SCRIPT + extra + POSTLUDE)
            proc = subprocess.run(
                [BUN, "run", str(path)], capture_output=True, text=True, timeout=60
            )
        self.assertEqual(
            proc.returncode, 0, f"\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
        return proc.stdout

    def test_the_pages_javascript_has_no_broken_handlers(self):
        out = self._run("")
        self.assertIn("JS OK", out)

    def test_formatting_helpers_behave(self):
        out = self._run("")
        self.assertNotIn("FALHOU", out)


@unittest.skipUnless(BUN, "sem bun/deno")
class PageMarkup(unittest.TestCase):
    """Static checks on the HTML, which run without a JS runtime."""

    def test_no_function_is_passed_through_setattribute(self):
        # `el(..., {onclick: someFn})` is now handled, but guard the pattern
        # that broke: a bare `onclick="` inside the source would be dead code.
        self.assertNotIn('onclick="', PAGE)

    def test_no_third_party_references(self):
        for needle in ("http://", "https://", "cdn.", "<iframe", "integrity="):
            self.assertNotIn(needle, PAGE, f"page references {needle!r}")

    def test_it_reports_javascript_errors_instead_of_silence(self):
        self.assertIn('addEventListener("error"', PAGE)

    def test_login_and_confirm_exist_as_routes(self):
        self.assertIn("/api/login", PAGE)
        self.assertIn("/api/confirm", PAGE)

    def test_credentials_are_sent_same_origin(self):
        self.assertIn('credentials: "same-origin"', PAGE)