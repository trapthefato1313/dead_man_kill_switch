"""Entrega de e-mail local: levanta um no SMTP (dmks.sink), envia-lhe uma
mensagem e mostra o recibo assinado. Nada sai para a Internet - o `To:` e apenas
um cabecalho; a mensagem fica no spool local.

    python3 scripts/demo_local_mail.py --to gsantos@binaryxz.com

Prova o mecanismo do no (transporte + recibo com SHA-256), nao a entrega externa.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import smtplib
import tempfile
import time
from email.message import EmailMessage
from pathlib import Path

from dmks.sink import Sink


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--to", default="eu@local", help="destinatario (so cabecalho)")
    parser.add_argument("--from", dest="sender", default="switch@dmks.invalid")
    parser.add_argument("--subject", default="Teste local MailNet")
    parser.add_argument("--body", default="Mensagem de teste entregue ao no local.\n")
    parser.add_argument("--spool", default=None, help="dir do spool (omisso: temporario)")
    args = parser.parse_args()

    spool = Path(args.spool) if args.spool else Path(tempfile.mkdtemp(prefix="dmks-mail-"))

    node = Sink(host="127.0.0.1", port=0, spool=spool, name="demo-node").start()
    print(f"no SMTP a escutar em 127.0.0.1:{node.port}  (spool: {spool})")

    msg = EmailMessage()
    msg["From"] = args.sender
    msg["To"] = args.to
    msg["Subject"] = args.subject
    msg.set_content(args.body)

    with smtplib.SMTP("127.0.0.1", node.port, timeout=10) as client:
        client.ehlo()
        client.send_message(msg)
    print(f"enviado para {args.to} (encerrado com 250)")

    time.sleep(0.1)
    node.stop()

    receipt = json.loads((spool / "receipts.jsonl").read_text().strip().splitlines()[-1])
    eml = spool / receipt["filename"]
    data = eml.read_bytes()
    ok = hashlib.sha256(data).hexdigest() == receipt["sha256"] and len(data) == receipt["size"]

    print("\n--- recibo ---")
    print(json.dumps(receipt, indent=2, ensure_ascii=False))
    print("\n--- mensagem gravada em", eml, "---")
    print(data.decode(errors="replace"))
    print("VERIFICACAO SHA-256:", "OK" if ok else "FALHOU")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
