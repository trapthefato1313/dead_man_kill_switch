"""End-to-end walkthrough: init -> enroll -> seal -> silence -> release -> decrypt.

Runs the real CLI against a real GnuPG key and a local webhook that stands in for
the delivery channel, then opens the delivered packet with the private key. If
this script completes, the whole chain works with no mocks.

    python3 scripts/demo_e2e.py

It writes everything under a temporary directory and never touches a real switch.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DAY = 86400
STEP = 12 * 3600

RECEIVED: list[dict] = []


class Capture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        RECEIVED.append(json.loads(self.rfile.read(length)))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def say(message: str) -> None:
    print(message, flush=True)


def dmks(data_dir: Path, *args: str, expect_ok: bool = True) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "dmks", "--data-dir", str(data_dir), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    if expect_ok and result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"comando falhou: dmks {' '.join(args)}")
    return result.stdout


def step(number: int, title: str) -> None:
    say(f"\n\033[1m{number}. {title}\033[0m")


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="dmks-demo-"))
    gnupg = workspace / "gnupg"
    data = workspace / "data"
    gnupg.mkdir(parents=True, mode=0o700)
    os.environ["GNUPGHOME"] = str(gnupg)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Capture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    hook = f"http://127.0.0.1:{server.server_port}/hook"

    try:
        step(1, "criar uma chave GnuPG de teste (o teu customer's nunca toca nisto)")
        subprocess.run(
            ["gpg", "--batch", "--quiet", "--passphrase", "", "--quick-generate-key",
             "Advogado <advogado@exemplo.pt>", "default", "default", "never"],
            check=True, capture_output=True,
        )
        listing = subprocess.run(
            ["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True
        ).stdout
        fingerprint = next(
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr")
        )
        say(f"   fingerprint: {fingerprint}")

        step(2, "init: Held release, 7/14/30 dias, tudo por omissao")
        out = dmks(data, "init", "--switch", "principal", "--name", "prova de vida",
                   "--release-mode", "notify", "--webhook-url", hook,
                   "--owner-email", "eu@exemplo.pt", "--warn-days", "7",
                   "--arm-days", "14", "--release-days", "30",
                   "--tick-seconds", str(STEP), "--force")
        say(out.rstrip())
        tick_token = next(
            line.split(": ", 1)[1] for line in out.splitlines() if line.startswith("tick token")
        )

        step(3, "enrolar dois dispositivos e guardar os secrets")
        phone_secret = "secret-do-telemovel"
        laptop_secret = "secret-do-portatil"
        dmks(data, "enroll", "--device", "phone", "--label", "telemovel",
             "--secret", phone_secret)
        dmks(data, "enroll", "--device", "laptop", "--label", "portatil",
             "--secret", laptop_secret)
        say("   phone e laptop enrolados; os secrets vivem nos dispositivos, nao no servidor")

        step(4, "destinatario: quem recebe, e com que chave")
        dmks(data, "recipient", "add", "--address", "advogado@exemplo.pt",
             "--gpg", fingerprint, "--webhook", hook)

        step(5, "selar a evidencia (o servidor nunca ve o texto claro)")
        evidence = workspace / "evidencia.txt"
        evidence.write_text(
            "Registo de comunicacoes threatening.\n"
            "Assinatura e contexto a verificar com o advogado.\n"
        )
        out = dmks(data, "seal", "--note", "comunicacoes de ameaca", str(evidence))
        say(out.rstrip())

        step(6, "check-in normal: os dois dispositivos vivos durante 6 dias")
        for _ in range(12):
            dmks(data, "checkin", "--device", "phone", "--secret", phone_secret)
            dmks(data, "checkin", "--device", "laptop", "--secret", laptop_secret)
            dmks(data, "tick")
            time.sleep(0.01)
        say("   " + json.loads(dmks(data, "status"))["state"])

        step(7, "silencio parcial: so o portatil desaparece, o quorum bloqueia")
        start = int(time.time()) - 40 * DAY
        backdate(data, start, device="laptop")
        summary = json.loads(dmks(data, "tick", "--now", str(start + STEP)))
        evaluation = summary["switches"][0]
        say(f"   estado: {evaluation['state']}")
        say(f"   quorum : {evaluation['quorum_met']}  silenciosos={evaluation['silent_devices']}")
        for note in evaluation["notes"]:
            say(f"   nota   : {note}")
        if evaluation["state"] != "ok":
            raise SystemExit("o quorum 'all' devia ter bloqueado a escalada")

        step(8, "os dois dispositivos param: a escalada percorre warn -> armed -> release")
        backdate(data, start, device="phone")
        moment = start
        for index in range(120):
            moment += STEP
            summary = json.loads(dmks(data, "tick", "--now", str(moment)))
            evaluation = summary["switches"][0]
            state = evaluation["state"]
            if state == "released":
                say(f"   dia {(moment - start) // DAY:>2}  {state}  <- entregue")
                break
            if evaluation["escalated"]:
                say(f"   dia {(moment - start) // DAY:>2}  {state}")
        else:
            raise SystemExit("o switch nao chegou a released")

        step(9, "o que foi entregue ao webhook")
        avisos = [i for i in RECEIVED if "packet" not in i]
        pacotes = [i for i in RECEIVED if "packet" in i]
        say(f"   {len(avisos)} aviso(s) ao dono e {len(pacotes)} entrega(s) do pacote")
        for item in avisos[:4]:
            say(f"     aviso: {item['subject']}")
        if len(avisos) > 4:
            say(f"     ... e mais {len(avisos) - 4} lembretes diarios")

        delivered = None
        for item in pacotes:
            packet = item["packet"]
            sealed = data / "packets" / packet["filename"]
            delivered = workspace / "recebido" / packet["filename"]
            delivered.parent.mkdir(parents=True, exist_ok=True)
            delivered.write_bytes(base64.b64decode(packet["content_b64"]))
            say(f"   pacote {packet['filename']}  sha256={packet['sha256'][:16]}...")
            say(f"   entregue == selado no servidor: {delivered.read_bytes() == sealed.read_bytes()}")
            break
        if delivered is None:
            raise SystemExit("nenhum pacote foi entregue")

        step(10, "o destinatario abre o pacote com a chave privada")
        opened = subprocess.run(
            ["gpg", "--batch", "--quiet", "--passphrase", "", "--decrypt",
             "--output", str(workspace / "aberto.txt"), str(delivered)],
            capture_output=True, text=True,
        )
        if opened.returncode != 0:
            print(opened.stderr, file=sys.stderr)
            raise SystemExit("nao foi possivel desencriptar o pacote entregue")
        say(f"   conteudo recuperado:\n{indent((workspace / 'aberto.txt').read_text())}")

        step(11, "auditoria: a cadeia conta a historia toda")
        verify = dmks(data, "verify")
        say("   " + "\n   ".join(verify.strip().splitlines()))
        export = json.loads(dmks(data, "export-audit"))
        say(f"   {export['entries']} entradas, verificadas={export['verified']}")
        say("   linha do tempo:")
        for entry in export["log"]:
            if entry["event"] == "state_change":
                detail = entry["detail"]
                say(f"     seq {entry['seq']:>2}  {detail['from']:>8} -> {detail['to']:<8}"
                    f" apos {detail['silenced_for'] // DAY} dias em silencio")

        say("\n\033[1mCadeia completa verificada.\033[0m")
        return 0
    finally:
        server.shutdown()
        shutil.rmtree(workspace, ignore_errors=True)


def indent(text: str) -> str:
    return "\n".join(f"     {line}" for line in text.strip().splitlines())


def backdate(data: Path, moment: int, device: str) -> None:
    subprocess.run(
        [sys.executable, "-c", BACKDATE, str(data), str(moment), device],
        check=True, cwd=ROOT,
    )


BACKDATE = """
import sqlite3, sys
data_dir, moment, device = sys.argv[1], int(sys.argv[2]), sys.argv[3]
conn = sqlite3.connect(f"{data_dir}/dmks.sqlite3")
if device == "all":
    conn.execute("UPDATE checkins SET at=?, client_ts=?", (moment, moment))
    conn.execute("UPDATE devices SET last_seen=?", (moment,))
else:
    conn.execute("UPDATE checkins SET at=?, client_ts=? WHERE device_id=?", (moment, moment, device))
    conn.execute("UPDATE devices SET last_seen=? WHERE id=?", (moment, device))
conn.execute("UPDATE switches SET created_at=? WHERE id='principal'", (moment - 365 * 86400,))
conn.execute(
    "INSERT INTO meta(key, value) VALUES('clock_watermark', ?) "
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    (str(moment),),
)
conn.commit()
"""


if __name__ == "__main__":
    raise SystemExit(main())