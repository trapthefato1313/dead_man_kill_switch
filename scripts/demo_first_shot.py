"""Primeiro disparo, de ponta a ponta, com anexo.

Levanta um no SMTP local (dmks.sink), cria um switch real que entrega por SMTP
para esse no, sela uma evidencia (o anexo), simula o silencio do dono e deixa a
escalada disparar ate `released`. Depois abre o e-mail que chegou ao no e confirma
que o anexo e exatamente o pacote selado no servidor.

    python3 scripts/demo_first_shot.py

Tudo local e real: SMTP a serio, GnuPG a serio, auditoria a serio. Nada sai para
a Internet.
"""

from __future__ import annotations

import email
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dmks.sink import Sink  # noqa: E402

DAY = 86400
STEP = 12 * 3600


def say(message: str) -> None:
    print(message, flush=True)


def step(number: int, title: str) -> None:
    say(f"\n\033[1m{number}. {title}\033[0m")


def dmks(data: Path, *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "dmks", "--data-dir", str(data), *args],
        capture_output=True, text=True, cwd=ROOT,
    )
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"comando falhou: dmks {' '.join(args)}")
    return result.stdout


def backdate(data: Path, moment: int) -> None:
    subprocess.run(
        [sys.executable, "-c", BACKDATE, str(data), str(moment)],
        check=True, cwd=ROOT,
    )


BACKDATE = """
import sqlite3, sys
data_dir, moment = sys.argv[1], int(sys.argv[2])
conn = sqlite3.connect(f"{data_dir}/dmks.sqlite3")
conn.execute("UPDATE checkins SET at=?, client_ts=?", (moment, moment))
conn.execute("UPDATE devices SET last_seen=?", (moment,))
conn.execute("UPDATE switches SET created_at=? WHERE id='principal'", (moment - 365 * 86400,))
conn.execute(
    "INSERT INTO meta(key, value) VALUES('clock_watermark', ?) "
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    (str(moment),),
)
conn.commit()
"""


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="dmks-shot-"))
    gnupg = workspace / "gnupg"
    data = workspace / "data"
    spool = workspace / "sink"
    gnupg.mkdir(parents=True, mode=0o700)
    os.environ["GNUPGHOME"] = str(gnupg)

    node = Sink(host="127.0.0.1", port=0, spool=spool, name="receptor").start()
    say(f"no SMTP local a escutar em 127.0.0.1:{node.port} (spool: {spool})")

    try:
        step(1, "chave GnuPG do destinatario (o servidor nunca ve o claro)")
        subprocess.run(
            ["gpg", "--batch", "--quiet", "--passphrase", "", "--quick-generate-key",
             "Jornalista <jornalista@exemplo.pt>", "default", "default", "never"],
            check=True, capture_output=True,
        )
        listing = subprocess.run(
            ["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True
        ).stdout
        fingerprint = next(
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr")
        )
        say(f"   fingerprint: {fingerprint}")

        step(2, "init: entrega por SMTP para o no local, 7/14/30 dias")
        dmks(data, "init", "--switch", "principal", "--name", "primeiro disparo",
             "--release-mode", "notify",
             "--smtp-host", "127.0.0.1", "--smtp-port", str(node.port),
             "--smtp-from", "switch@dmks.invalid",
             "--owner-email", "eu@local",
             "--warn-days", "7", "--arm-days", "14", "--release-days", "30",
             "--tick-seconds", str(STEP), "--force")

        # O no local nao fala STARTTLS; desliga-o para o teste (num relay real fica true).
        cfg_path = data / "config.json"
        cfg = json.loads(cfg_path.read_text())
        cfg["server"]["smtp_starttls"] = False
        cfg_path.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        say("   smtp_starttls=false (no local nao fala STARTTLS)")

        step(3, "enrolar dispositivos e registar o destinatario")
        dmks(data, "enroll", "--device", "phone", "--label", "telemovel",
             "--secret", "s1")
        dmks(data, "enroll", "--device", "laptop", "--label", "portatil",
             "--secret", "s2")
        dmks(data, "recipient", "add", "--address", "jornalista@exemplo.pt",
             "--gpg", fingerprint)
        # Sem pelo menos um check-in, o motor mede o silencio desde a criacao do
        # switch (nunca houve prova de vida). Isto poe a linha do tempo a contar
        # do ultimo sinal de vida, que e o que queremos demonstrar.
        dmks(data, "checkin", "--device", "phone", "--secret", "s1")
        dmks(data, "checkin", "--device", "laptop", "--secret", "s2")
        dmks(data, "tick")

        step(4, "selar a evidencia (isto vira o ANEXO do e-mail)")
        evidence = workspace / "evidencia.txt"
        evidence.write_text(
            "Prova 1: contrato assinado.\n"
            "Prova 2: registo de transferencias.\n"
            "Prova 3: testemunho do advogado.\n"
        )
        out = dmks(data, "seal", "--note", "dossier completo", str(evidence))
        say("   " + "\n   ".join(out.strip().splitlines()))

        step(5, "o dono desaparece: warn -> armed -> released")
        start = int(time.time()) - 40 * DAY
        backdate(data, start)
        moment = start
        for _ in range(120):
            moment += STEP
            summary = json.loads(dmks(data, "tick", "--now", str(moment)))
            state = summary["switches"][0]["state"]
            if state == "released":
                say(f"   dia {(moment - start) // DAY:>2}  released  <- DISPAROU")
                break
        else:
            raise SystemExit("o switch nao chegou a released")

        time.sleep(0.3)
        step(6, "o que chegou ao no SMTP")
        receipts = [json.loads(line) for line in (spool / "receipts.jsonl").read_text().splitlines()]
        say(f"   {len(receipts)} mensagem(ns) recebida(s) pelo no")

        release = None
        for receipt in receipts:
            raw = (spool / receipt["filename"]).read_bytes()
            msg = email.message_from_bytes(raw)
            if "pacote selado" in msg.get("Subject", ""):
                release = (receipt, msg)
                break
        if release is None:
            raise SystemExit("nenhum e-mail de release com anexo chegou")

        receipt, msg = release
        say(f"   assunto : {msg.get('Subject')}")
        say(f"   para    : {msg.get('To')}")
        attachments = [p for p in msg.walk() if p.get_filename()]
        say(f"   anexos  : {[p.get_filename() for p in attachments]}")

        attachment = attachments[0]
        arrived = attachment.get_payload(decode=True)
        sealed = data / "packets" / attachment.get_filename()
        say(f"   anexo sha256 chegou : {' '.join('%02x' % b for b in __import__('hashlib').sha256(arrived).digest()[:8])}...")
        say(f"   anexo == pacote selado no servidor: {arrived == sealed.read_bytes()}")

        step(7, "auditoria")
        verify = dmks(data, "verify")
        say("   " + "\n   ".join(verify.strip().splitlines()))

        if arrived != sealed.read_bytes():
            raise SystemExit("o anexo entregue nao corresponde ao pacote selado")
        say("\n\033[1mPrimeiro disparo verificado: o anexo chegou intacto.\033[0m")
        return 0
    finally:
        node.stop()
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
