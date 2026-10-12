#!/usr/bin/env python3
"""Teste REAL de disparo: sai por SMTP externo e cai numa caixa a serio.

Ao contrario do `demo_first_shot.py` (que entrega num no local), este script
aponta o switch a um relay SMTP VERDADEIRO e deixa a escada disparar ate
`released`, entregando o pacote selado ao destinatario `--to`.

Prova o caminho externo ponta-a-ponta. Se a entrega falhar, mostra o erro exato
do servidor de destino (auth, TLS, relay denied, etc.).

Exemplos:

    # relay com STARTTLS + login (Brevo/SendGrid/Mailgun/teu Stalwart, ...)
    export DMKS_SMTP_PASS='a-tua-password'
    python3 scripts/real_test.py \
        --to gsantos@binaryxz.com \
        --from switch@o-teu-dominio.com \
        --smtp-host smtp.exemplo.com --smtp-port 587 \
        --smtp-user 'utilizador' --smtp-pass env:DMKS_SMTP_PASS

    # MTA direto na rede, sem login nem STARTTLS
    python3 scripts/real_test.py --to ... --from ... \
        --smtp-host mx.exemplo.com --smtp-port 25 --no-starttls

    # auto-teste contra um no local (NAO sai para a Internet)
    python3 scripts/real_test.py --to teste@local --from switch@x \
        --smtp-host 127.0.0.1 --smtp-port 2525 --no-starttls --self-sink

    # cifrar para a TUA chave publica (senao gera uma descartavel)
    python3 scripts/real_test.py ... --pubkey a-minha-chave.pub
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DAY = 86400
STEP = 12 * 3600


def say(message: str = "") -> None:
    print(message, flush=True)


def step(number: int, title: str) -> None:
    say(f"\n\033[1m{number}. {title}\033[0m")


def dmks(data: Path, *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "dmks", "--data-dir", str(data), *args],
        capture_output=True, text=True, cwd=ROOT,
    )
    if result.returncode != 0:
        say(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"comando falhou: dmks {' '.join(args)}")
    return result.stdout


def backdate(data: Path, moment: int) -> None:
    conn = sqlite3.connect(f"{data}/dmks.sqlite3")
    conn.execute("UPDATE checkins SET at=?, client_ts=?", (moment, moment))
    conn.execute("UPDATE devices SET last_seen=?", (moment,))
    conn.execute("UPDATE switches SET created_at=? WHERE id='principal'", (moment - 365 * DAY,))
    conn.execute(
        "INSERT INTO meta(key, value) VALUES('clock_watermark', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(moment),),
    )
    conn.commit()
    conn.close()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Teste real de disparo por SMTP externo")
    p.add_argument("--to", required=True, help="destinatario real (ex.: gsantos@binaryxz.com)")
    p.add_argument("--from", dest="sender", required=True, help="remetente (deve casar com SPF/dominio)")
    p.add_argument("--smtp-host", required=True)
    p.add_argument("--smtp-port", type=int, default=587)
    p.add_argument("--smtp-user")
    p.add_argument("--smtp-pass", help="valor literal ou 'env:VAR' (recomendado)")
    tls = p.add_mutually_exclusive_group()
    tls.add_argument("--starttls", dest="starttls", action="store_true", default=True)
    tls.add_argument("--no-starttls", dest="starttls", action="store_false")
    p.add_argument("--pubkey", help="ficheiro .pub para cifrar o pacote (senao gera descartavel)")
    p.add_argument("--data-dir", help="onde deixar os artefactos (omisso: temporario)")
    p.add_argument("--keep", action="store_true", help="nao apagar o data-dir no fim")
    p.add_argument("--self-sink", action="store_true", help="levanta um no local (auto-teste)")
    return p


def main() -> int:
    args = parser().parse_args()

    workspace = Path(args.data_dir) if args.data_dir else Path(tempfile.mkdtemp(prefix="dmks-real-"))
    workspace.mkdir(parents=True, exist_ok=True)
    data = workspace / "data"
    gnupg = workspace / "gnupg"
    gnupg.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.environ["GNUPGHOME"] = str(gnupg)

    node = None
    if args.self_sink:
        from dmks.sink import Sink

        node = Sink(host="127.0.0.1", port=0, spool=workspace / "sink", name="self").start()
        args.smtp_host, args.smtp_port, args.starttls = "127.0.0.1", node.port, False
        say(f"no local a escutar em 127.0.0.1:{node.port} (auto-teste)")

    try:
        step(1, "chave GnuPG de cifragem")
        if args.pubkey:
            subprocess.run(["gpg", "--import", args.pubkey], check=True, capture_output=True)
        else:
            subprocess.run(
                ["gpg", "--batch", "--quiet", "--passphrase", "", "--quick-generate-key",
                 f"Teste <teste@dmks.invalid>", "default", "default", "never"],
                check=True, capture_output=True,
            )
        listing = subprocess.run(
            ["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True
        ).stdout
        fingerprint = next(
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr")
        )
        say(f"   fingerprint: {fingerprint}")

        step(2, f"init -> entrega por {args.smtp_host}:{args.smtp_port} (starttls={args.starttls})")
        init_args = [
            "init", "--switch", "principal", "--name", "teste real",
            "--release-mode", "notify",
            "--smtp-host", args.smtp_host, "--smtp-port", str(args.smtp_port),
            "--smtp-from", args.sender,
            "--owner-email", args.to,
            "--warn-days", "7", "--arm-days", "14", "--release-days", "30",
            "--tick-seconds", str(STEP), "--force",
        ]
        if args.smtp_user:
            init_args += ["--smtp-user", args.smtp_user]
        if args.smtp_pass:
            init_args += ["--smtp-password", args.smtp_pass]
        dmks(data, *init_args)

        if not args.starttls:
            cfg_path = data / "config.json"
            cfg = json.loads(cfg_path.read_text())
            cfg["server"]["smtp_starttls"] = False
            cfg_path.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n")
            say("   smtp_starttls=false")

        step(3, "enrolar dispositivo, registar destinatario, check-in")
        dmks(data, "enroll", "--device", "phone", "--label", "telemovel", "--secret", "s1")
        dmks(data, "recipient", "add", "--address", args.to, "--gpg", fingerprint, "--owner")
        dmks(data, "checkin", "--device", "phone", "--secret", "s1")
        dmks(data, "tick")
        say(f"   destinatario: {args.to}")

        step(4, "selar a evidencia (o ANEXO do e-mail)")
        evidence = workspace / "evidencia.txt"
        evidence.write_text(
            "Teste real do dead man's switch.\n"
            f"Para: {args.to}\n"
            f"Quando: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
            "Isto nao e uma ameaca nem um disparo a serio: e um teste de entrega.\n"
        )
        out = dmks(data, "seal", "--note", "teste de entrega real", str(evidence))
        say("   " + out.strip().splitlines()[0])

        step(5, "o dono desaparece: warn -> armed -> released")
        start = int(time.time()) - 40 * DAY
        backdate(data, start)
        moment = start
        released = False
        for _ in range(120):
            moment += STEP
            summary = json.loads(dmks(data, "tick", "--now", str(moment)))
            if summary["switches"][0]["state"] == "released":
                released = True
                say(f"   dia {(moment - start) // DAY:>2}  released  <- DISPAROU")
                break
        if not released:
            raise SystemExit("o switch nao chegou a released")

        # Alguns ticks extra permitem novos ensaios se o primeiro SMTP falhar.
        for extra in range(1, 4):
            moment += STEP
            dmks(data, "tick", "--now", str(moment))

        step(6, "resultado da entrega (o que o servidor respondeu)")
        conn = sqlite3.connect(f"{data}/dmks.sqlite3")
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute(
            "SELECT target, channel, ok, attempts, last_error FROM deliveries "
            "WHERE mode='release' ORDER BY at DESC"
        ))
        ok_any = False
        for r in rows:
            mark = "OK " if r["ok"] else "ERRO"
            say(f"   [{mark}] {r['target']:<32} canal={r['channel'] or '-':<24} "
                f"tentativas={r['attempts']}  {r['last_error'] or ''}")
            ok_any = ok_any or bool(r["ok"])
        conn.close()

        verify = dmks(data, "verify")
        say("   auditoria: " + " | ".join(verify.strip().splitlines()[-2:]))

        if args.self_sink and node is not None:
            time.sleep(0.3)
            node.stop()
            emls = list((workspace / "sink").glob("*.eml"))
            say(f"   mensagens no no local: {len(emls)}")

        say()
        if ok_any:
            say("\033[1mENTREGUE.\033[0m Confirma na caixa "
                f"{args.to}: assunto '[dead man's switch] ... pacote selado ...' com anexo .gpg.")
            say("Se nao aparecer em minutos, verifica a pasta de spam e o Postmaster Tools.")
        else:
            say("\033[1mNAO ENTREGUE.\033[0m Le o erro acima (auth/TLS/relay). "
                "Porta 25 bloqueada? Usa um relay em 587 com login.")

        if args.data_dir:
            say(f"\nartefactos em: {data}")
        return 0 if ok_any else 2
    finally:
        if node is not None:
            node.stop()
        if not args.keep and not args.data_dir:
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
