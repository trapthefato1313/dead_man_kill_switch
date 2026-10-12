"""The panel.

One file, no framework, no CDN, no external request of any kind. A dead man's
switch is read by one frightened person at three in the morning; it must load
on a bad connection, and a script tag pointing at somebody else's server is a
decision this tool should never make.

The page is deliberately honest. It shows the countdown to firing, not a
reassuring green tick, and it says plainly when the clock is frozen or when the
release is being held.
"""

from __future__ import annotations

PAGE = """<!doctype html>
<html lang="pt">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>dead man's switch</title>
<style>
:root{
  --bg:#0b0c0e; --panel:#141619; --line:#262a30; --ink:#e8eaed;
  --dim:#8b929c; --warn:#e0a63a; --armed:#e2703a; --live:#4ec98a;
  --dead:#e5484d; --frozen:#8b7fe8; --accent:#4a9de8;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:720px;margin:0 auto;padding:24px 20px 72px}
h1{font-size:15px;font-weight:600;letter-spacing:.02em;margin:0 0 2px}
.sub{color:var(--dim);font-size:13px;margin:0 0 26px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:20px;margin-bottom:16px}
.state{text-align:center;padding:26px 20px}
.state .word{font-size:34px;font-weight:700;letter-spacing:-.02em;line-height:1.1}
.state .why{color:var(--dim);font-size:13px;margin-top:6px}
.ok .word{color:var(--live)} .warn .word{color:var(--warn)}
.armed .word{color:var(--armed)} .released .word{color:var(--dead)}
.frozen .word{color:var(--frozen)}
.count{font-variant-numeric:tabular-nums;font-size:52px;font-weight:700;
  letter-spacing:-.03em;line-height:1;text-align:center;margin:6px 0 2px}
.countlab{text-align:center;color:var(--dim);font-size:13px}
.count.over .count{color:var(--dead)}
.track{position:relative;height:10px;background:#1d2126;border-radius:6px;
  margin:22px 0 8px;overflow:hidden}
.fill{height:100%;background:var(--accent);border-radius:6px;transition:width .4s}
.fill.warn{background:var(--warn)} .fill.armed{background:var(--armed)}
.fill.dead{background:var(--dead)}
.mark{position:absolute;top:-4px;width:2px;height:18px;background:#4a5058}
.legend{display:flex;justify-content:space-between;font-size:11px;color:var(--dim);
  font-variant-numeric:tabular-nums}
button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--line);
  background:#1d2126;color:var(--ink);padding:10px 16px}
button:hover:not(:disabled){background:#242930}
button:disabled{opacity:.45;cursor:not-allowed}
.big{width:100%;padding:18px;font-size:17px;font-weight:600;margin-top:4px}
.big.ok:hover:not(:disabled){background:#17301f;border-color:#2f6b45}
input{font:inherit;width:100%;padding:12px 14px;border-radius:8px;
  border:1px solid var(--line);background:#0f1114;color:var(--ink)}
input:focus{outline:none;border-color:var(--accent)}
label{display:block;font-size:12px;color:var(--dim);margin:14px 0 5px}
.row{display:flex;gap:10px;margin-top:14px}
.kv{display:flex;justify-content:space-between;gap:16px;padding:9px 0;
  border-bottom:1px solid var(--line);font-size:13.5px}
.kv:last-child{border-bottom:0}
.kv b{font-weight:600;text-align:right;font-variant-numeric:tabular-nums}
.kv span{color:var(--dim)}
.note{font-size:12.5px;line-height:1.5;padding:10px 12px;border-radius:7px;
  background:#1a1d22;border-left:2px solid var(--warn);margin-bottom:12px;
  color:#d6dae0}
.note.bad{border-left-color:var(--dead)} .note.info{border-left-color:var(--accent)}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;background:#0f1114;
  padding:2px 6px;border-radius:4px;color:#b9c0c9;word-break:break-all}
.receipt{display:none;margin-top:14px;padding:12px;border-radius:7px;
  background:#12211a;border:1px solid #234d38}
.receipt.show{display:block}
.err{display:none;margin-top:10px;color:#ff8a8d;font-size:13px}
.err.show{display:block}
.hide{display:none!important}
</style>
</head>
<body>
<div class="wrap">
  <h1>dead man's switch</h1>
  <p class="sub" id="sub">a carregar&hellip;</p>
  <div id="app"></div>
</div>

<script>
const $ = (s, r) => (r || document).querySelector(s);
const el = (t, a, kids) => {
  const n = document.createElement(t);
  for (const k in (a || {})) {
    const v = a[k];
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    // A function must become a property. setAttribute("onclick", fn) would
    // stringify it into inline JS source and silently attach nothing, which is
    // how the login button ended up dead.
    else if (typeof v === "function") n[k] = v;
    else n.setAttribute(k, v);
  }
  (kids || []).forEach(c => n.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
  return n;
};

/* A silent JS failure in this page looks identical to "the server is down".
   Make it loud instead. */
window.addEventListener("error", ev => {
  const b = document.getElementById("sub");
  if (b) b.textContent = "erro de JavaScript: " + (ev.message || ev.type) +
    " (linha " + (ev.lineno || "?") + ")";
});

const DAYS = 86400;
const fmtD = s => {
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / DAYS);
  const h = Math.floor((s % DAYS) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  return m + "m";
};
const when = ts => ts ? new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + "Z" : "nunca";

let P = null;

async function api(path, body) {
  const opt = { method: body ? "POST" : "GET", credentials: "same-origin" };
  if (body) {
    opt.headers = { "Content-Type": "application/json" };
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({ error: "resposta invalida" }));
  if (!r.ok) throw new Error(j.error || r.status);
  return j;
}

/* ---------- login ---------- */
function login(msg) {
  $("#app").replaceChildren();
  const input = el("input", { type: "password", id: "pw", placeholder: "palavra-passe do dono" });
  const err = el("div", { class: "err" });
  const card = el("div", { class: "card" }, [
    el("label", {}, ["Palavra-passe do dono"]),
    input,
    el("div", { class: "row" }, [el("button", { class: "big ok", onclick: go }, ["Entrar"])]),
    err,
  ]);
  if (msg) { err.textContent = msg; err.classList.add("show"); }
  $("#app").replaceChildren(card);
  input.focus();
  input.addEventListener("keydown", e => { if (e.key === "Enter") go(); });
  async function go() {
    err.classList.remove("show");
    try {
      await api("/api/login", { password: input.value });
      await boot();
    } catch (e) { err.textContent = e.message; err.classList.add("show"); }
  }
}

/* ---------- panel ---------- */
function render() {
  const d = P, app = $("#app");
  const s = d.status;
  const st = s.state;
  const held = s.release_mode === "hold";

  const over = s.seconds_to_release === 0;
  const left = over ? -s.silenced_for_seconds + s.seconds_to_release : s.seconds_to_release;
  const ratio = Math.min(1, s.silenced_for_seconds / Math.max(1, s.release_after_seconds));
  const cls = ratio >= 1 ? "dead" : ratio >= (s.arm_after_seconds / s.release_after_seconds) ? "armed"
    : ratio >= (s.warn_after_seconds / s.release_after_seconds) ? "warn" : "";

  const word = { ok: "OK", warn: "AVISO", armed: "ARMADO", released: "LIBERTADO" }[st] || st;
  const why = {
    ok: "silencio dentro do prazo",
    warn: "ninguem fez check-in a tempo",
    armed: "o pacote esta preparado e aguarda",
    released: "o pacote saiu. ja nao ha volta.",
  }[st] || "";

  const banner = el("div", { class: "card state " + st }, [
    el("div", { class: "word" }, [word]),
    el("div", { class: "why" }, [why]),
  ]);

  const marks = [];
  [["warn", s.warn_after_seconds], ["arm", s.arm_after_seconds], ["release", s.release_after_seconds]]
    .forEach(([k, v]) => marks.push(el("div", {
      class: "mark", title: k + " dia " + Math.round(v / DAYS),
      style: "left:" + Math.min(100, (v / s.release_after_seconds) * 100) + "%",
    })));

  const track = el("div", { class: "track" }, [el("div", { class: "fill " + cls, style: "width:" + (ratio * 100) + "%" })].concat(marks));

  const countdown = el("div", { class: "card" }, [
    over
      ? el("div", { class: "count over" }, ["EXCEDIDO"])
      : el("div", { class: "count" + (ratio >= 1 ? " over" : "") }, [fmtD(left)]),
    el("div", { class: "countlab" }, [
      over ? "silencio ja ultrapassou o prazo de liberacao" : "ate a liberacao automatica",
    ]),
    track,
    el("div", { class: "legend" }, [
      el("span", {}, ["agora"]),
      el("span", {}, ["aviso " + Math.round(s.warn_after_seconds / DAYS) + "d"]),
      el("span", {}, ["armado " + Math.round(s.arm_after_seconds / DAYS) + "d"]),
      el("span", {}, ["liberta " + Math.round(s.release_after_seconds / DAYS) + "d"]),
    ]),
  ]);

  /* notes: the system explains itself */
  const notes = [];
  if (d.clock && d.clock.status === "disagree")
    notes.push(["bad", "Relogios em desacordo. A escalada esta CONGELADA para nao disparar com a hora errada.Corrige o NTP ou o sistema nao avanca."]);
  else if (d.clock && d.clock.status === "uncorroborated")
    notes.push(["info", "Sem fonte de tempo externa. Um salto grande do relogio fica limitado a " + Math.round(d.clock.max_credit / DAYS) + " dias por avaliacao."]);
  if (held)
    notes.push(["bad", "release_mode = hold: NADA sera enviado mesmo no estado ARMADO. Isto e propositado num servidor novo, mas mata o switch se ficares assim."]);
  if (over && st !== "released")
    notes.push(["bad", "O silencio ja passou do prazo mas o estado ainda nao mudou. Corrige o relogio e corre um tick."]);
  (s.notes || []).forEach(n => notes.push(["info", n]));

  const noteBox = notes.length
    ? el("div", {}, notes.map(([k, t]) => el("div", { class: "note " + k }, [t])))
    : el("div");

  /* check-in */
  const pw = el("input", { type: "password", placeholder: "a tua palavra-passe, outra vez" });
  const err = el("div", { class: "err" });
  const rec = el("div", { class: "receipt" });
  const btn = el("button", { class: "big ok" }, ["Estou vivo  ·  check-in"]);
  btn.onclick = async () => {
    btn.disabled = true;
    err.classList.remove("show");
    rec.classList.remove("show");
    try {
      const r = await api("/api/confirm", { password: pw.value });
      pw.value = "";
      const q = r.receipt;
      rec.replaceChildren(
        el("div", { style: "font-weight:600;margin-bottom:6px" }, ["Check-in registado."]),
        el("div", { style: "font-size:12.5px;color:#9fd8bb" },
          ["Estado " + r.from_state + " -> " + r.state + ". Guarda este recibo."]),
        el("div", { style: "margin-top:8px;font-size:12px;color:var(--dim)" }, ["cadeia de auditoria, entrada " + q.audit_seq]),
        el("div", { style: "margin-top:3px" }, [el("code", {}, [q.audit_hash])]),
      );
      rec.classList.add("show");
      await boot(true);
    } catch (e) {
      err.textContent = e.message;
      err.classList.add("show");
      btn.disabled = false;
    }
  };
  pw.addEventListener("keydown", e => { if (e.key === "Enter") btn.click(); });

  const checkin = el("div", { class: "card" }, [
    el("div", { style: "font-weight:600" }, ["Prova de vida"]),
    el("div", { style: "font-size:12.5px;color:var(--dim);margin-top:3px" },
      ["So tu podes fazer isto. E o que impede um automatismo de manter o switch adormecido."]),
    el("label", {}, ["palavra-passe"]),
    pw,
    el("div", { class: "row" }, [btn]),
    err, rec,
  ]);

  const kv = (k, v) => el("div", { class: "kv" }, [el("span", {}, [k]), el("b", {}, [String(v)])]);
  const facts = el("div", { class: "card" }, [
    kv("Ultimo check-in", when(s.last_checkin_at)),
    kv("Silencio", fmtD(s.silenced_for_seconds)),
    kv("Confirmacoes", s.confirmations),
    kv("Quorum", s.quorum),
    kv("Dispositivos mudos", s.silent_devices.length ? s.silent_devices.join(", ") : "nenhum"),
    kv("Pacotes selados", s.packets.length || "nenhum"),
    kv("Destinatarios", (s.recipients || []).length),
    kv("Modo de liberacao", s.release_mode),
    kv("Cadeia de auditoria", d.audit.ok ? "intacta (" + d.audit.count + ")" : "ALTERADA: " + d.audit.reason),
    kv("Marca de agua", when(d.watermark)),
  ]);

  app.replaceChildren(banner, countdown, noteBox, checkin, facts);
}

async function boot(quiet) {
  try {
    P = await api("/api/panel");
    $("#sub").textContent = P.status.name + "  ·  " + new Date().toISOString().slice(0, 10);
    render();
  } catch (e) {
    if (!quiet) login(e.message === "no session" ? "" : e.message);
  }
}
boot();
</script>
</body>
</html>
"""