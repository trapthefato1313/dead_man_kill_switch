"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from . import audit, config as config_mod, deliver, engine, liveness, runner, seal, store

DEFAULT_DATA_DIR = "data"


def _load(args) -> tuple[config_mod.Config, sqlite3.Connection]:
    data_dir = Path(args.data_dir).expanduser()
    cfg = config_mod.load(data_dir)
    conn = store.connect(cfg.db_path)
    return cfg, conn


def _switch(conn, switch_id: str):
    row = store.get_switch(conn, switch_id)
    if row is None:
        raise SystemExit(f"unknown switch: {switch_id}")
    return row


def _resolve(conn, args) -> str:
    if getattr(args, "switch", None):
        return args.switch
    switches = store.list_switches(conn)
    if len(switches) == 1:
        return switches[0]["id"]
    if not switches:
        raise SystemExit("no switches configured; run `dmks init` first")
    raise SystemExit("several switches exist; pass --switch")


# --- setup ---------------------------------------------------------------


def cmd_init(args) -> int:
    data_dir = Path(args.data_dir).expanduser()
    if data_dir.exists() and (data_dir / "config.json").exists() and not args.force:
        raise SystemExit(f"{data_dir}/config.json already exists; pass --force to overwrite")

    audit_key = config_mod.new_audit_key()
    cfg = config_mod.Config(data_dir=data_dir, audit_key=audit_key)
    cfg.server.host = args.host
    cfg.server.port = args.port
    cfg.server.tick_seconds = args.tick_seconds
    cfg.server.owner_email = args.owner_email
    cfg.server.tick_token = secrets.token_urlsafe(32)
    cfg.server.smtp_host = args.smtp_host
    cfg.server.smtp_port = args.smtp_port
    cfg.server.smtp_from = args.smtp_from
    cfg.server.webhook_url = args.webhook_url
    cfg.server.publish_dir = args.publish_dir

    switch = config_mod.SwitchConfig(
        name=args.name,
        warn_after=args.warn_days * config_mod.DAY,
        arm_after=args.arm_days * config_mod.DAY,
        release_after=args.release_days * config_mod.DAY,
        release_mode=args.release_mode,
    )
    cfg.switches[args.switch] = switch
    config_mod.save(cfg)

    cfg.packets_dir.mkdir(parents=True, exist_ok=True)
    conn = store.connect(cfg.db_path)
    with store.tx(conn):
        store.create_switch(
            conn,
            args.switch,
            name=switch.name,
            owner_key=liveness.owner_key_hex(secrets.token_urlsafe(32)),
            recipients=[],
            now=int(time.time()),
            **{
                "warn_after": switch.warn_after,
                "arm_after": switch.arm_after,
                "release_after": switch.release_after,
                "device_grace": switch.device_grace,
                "quorum_mode": switch.quorum_mode,
                "quorum_n": switch.quorum_n,
                "confirmations": switch.confirmations,
                "release_mode": switch.release_mode,
                "clock_skew": switch.clock_skew,
            },
        )
        audit.append(conn, audit_key, int(time.time()), "init", {"switch": args.switch})

    print(f"data dir : {data_dir.resolve()}")
    print(f"switch   : {args.switch} ({switch.name})")
    print(f"auditoria: chave {audit.key_fingerprint(audit_key)}")
    print(f"tick token: {cfg.server.tick_token}")
    print()
    print("Proximo passo: enrola um dispositivo com `dmks enroll`.")
    return 0


# --- devices -------------------------------------------------------------


def cmd_enroll(args) -> int:
    cfg, conn = _load(args)
    switch_id = _resolve(conn, args)
    now = int(time.time())
    secret = args.secret or liveness.new_secret()
    with store.tx(conn):
        store.add_device(conn, args.device, switch_id, args.label, liveness.device_key_hex(secret), now)
        audit.append(conn, cfg.audit_key, now, "device_enrolled",
                     {"switch": switch_id, "device": args.device, "label": args.label})
    print(f"device     : {args.device}")
    print(f"switch     : {switch_id}")
    print(f"secret     : {secret}")
    print()
    if args.secret:
        print("Usaste --secret, por isso este comando nao pode volver a mostrar o valor.")
        print("Confirma que o guardaste no dispositivo antes de saires daqui.")
    else:
        print("Guarda este secret. Nao aparece outra vez e o servidor nunca o consegue")
        print("reconstruir. Sem ele o dispositivo nao consegue fazer check-in.")
        print("Para mais controlo, gera o secret no dispositivo e usa --secret.")
    return 0


def cmd_retire(args) -> int:
    cfg, conn = _load(args)
    device = store.get_device(conn, args.device)
    if device is None:
        raise SystemExit(f"unknown device: {args.device}")
    now = int(time.time())
    with store.tx(conn):
        store.retire_device(conn, args.device, now)
        audit.append(conn, cfg.audit_key, now, "device_retired",
                     {"device": args.device, "switch": device["switch_id"]})
    print(f"device {args.device} retired")
    return 0


def cmd_devices(args) -> int:
    _, conn = _load(args)
    switch_id = _resolve(conn, args)
    for device in store.list_devices(conn, switch_id, enabled_only=False):
        seen = device["last_seen"]
        state = "enabled" if device["enabled"] else "retired"
        print(f"{device['id']:<16} {state:<9} {device['label']:<20} last_seen={seen}")
    return 0


# --- recipients ----------------------------------------------------------


def cmd_recipient(args) -> int:
    cfg, conn = _load(args)
    switch_id = _resolve(conn, args)
    switch = _switch(conn, switch_id)
    recipients = json.loads(switch["recipients"])

    if args.action == "add":
        entry = {"address": args.address, "owner": bool(args.owner)}
        if args.gpg:
            entry["gpg"] = args.gpg
        if args.webhook:
            entry["kind"] = "webhook"
            entry["address"] = args.webhook
        recipients = [r for r in recipients if r.get("address") != entry["address"]]
        recipients.append(entry)
    else:
        recipients = [r for r in recipients if r.get("address") != args.address]

    with store.tx(conn):
        conn.execute("UPDATE switches SET recipients=? WHERE id=?", (json.dumps(recipients), switch_id))
        audit.append(conn, cfg.audit_key, int(time.time()), "recipients_changed",
                     {"switch": switch_id, "count": len(recipients)})

    cfg.switches.setdefault(switch_id, config_mod.SwitchConfig(name=switch["name"])).recipients = recipients
    problems = config_mod.validate(cfg)
    config_mod.save(cfg)
    print(json.dumps(recipients, indent=2))
    if problems:
        print("\navisos de configuracao:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
    return 0


# --- sealing -------------------------------------------------------------


def cmd_seal(args) -> int:
    cfg, conn = _load(args)
    switch_id = _resolve(conn, args)
    switch = _switch(conn, switch_id)
    recipients = json.loads(switch["recipients"])
    keys = [r["gpg"] for r in recipients if r.get("gpg")]
    if not keys:
        raise SystemExit("no recipient with --gpg configured; add one with `dmks recipient add`")

    cfg.packets_dir.mkdir(parents=True, exist_ok=True)
    packet_id = f"p{int(time.time())}"
    output = cfg.packets_dir / f"{packet_id}.gpg"

    inputs = [Path(p) for p in args.files]
    for path in inputs:
        if not path.exists():
            raise SystemExit(f"missing input: {path}")

    digest = seal.seal(inputs, keys, output)
    problems = seal.verify_container(output, digest, keys)
    if problems:
        output.unlink(missing_ok=True)
        raise SystemExit("refused to seal, verification failed:\n  " + "\n  ".join(problems))

    now = int(time.time())
    with store.tx(conn):
        store.add_packet(conn, packet_id, switch_id, output.name, digest, output.stat().st_size,
                         recipients, args.note, now)
        audit.append(conn, cfg.audit_key, now, "packet_sealed",
                     {"switch": switch_id, "packet": packet_id, "sha256": digest,
                      "size": output.stat().st_size, "recipients": keys})
    print(f"packet   : {packet_id}")
    print(f"file     : {output}")
    print(f"sha256   : {digest}")
    print(f"size     : {output.stat().st_size} bytes")
    print("verified : gpg ok, hash ok, addressed to enrolled keys")
    print()
    print("Guarda uma copia deste ficheiro noutro sitio. Se o servidor perder o")
    print("disco depois de ti, o pacote vai com ele.")
    return 0


def cmd_packets(args) -> int:
    _, conn = _load(args)
    switch_id = _resolve(conn, args)
    for packet in store.active_packets(conn, switch_id):
        print(f"{packet['id']:<14} {packet['size']:>9} bytes  {packet['sha256'][:16]}  {packet['note'] or ''}")
    return 0


# --- operation -----------------------------------------------------------


def cmd_arm(args) -> int:
    cfg, conn = _load(args)
    switch_id = _resolve(conn, args)
    switch = _switch(conn, switch_id)
    now = int(time.time())
    updates: dict[str, object] = {}
    if args.release_mode:
        updates["release_mode"] = args.release_mode
    if args.release_days is not None:
        updates["release_after"] = args.release_days * config_mod.DAY
    if args.confirmations is not None:
        updates["confirmations"] = args.confirmations
    if not updates:
        raise SystemExit("nothing to change; pass --release-mode, --release-days or --confirmations")

    sets = ", ".join(f"{k}=?" for k in updates)
    with store.tx(conn):
        conn.execute(f"UPDATE switches SET {sets} WHERE id=?", (*updates.values(), switch_id))
        audit.append(conn, cfg.audit_key, now, "reconfigured",
                     {"switch": switch_id, "changes": {k: str(v) for k, v in updates.items()}})

    definition = cfg.switches.setdefault(switch_id, config_mod.SwitchConfig(name=switch["name"]))
    for key, value in updates.items():
        setattr(definition, key, value)
    config_mod.save(cfg)

    fresh = _switch(conn, switch_id)
    problems = config_mod.validate(cfg)
    print(f"switch {switch_id}: {fresh['release_mode']} release={fresh['release_after']}s "
          f"confirmations={fresh['confirmations']}")
    for problem in problems:
        print(f"  aviso: {problem}", file=sys.stderr)
    return 0


def cmd_status(args) -> int:
    _, conn = _load(args)
    now = int(args.now) if getattr(args, "now", None) else int(time.time())
    rows = [args.switch] if getattr(args, "switch", None) else [s["id"] for s in store.list_switches(conn)]
    for switch_id in rows:
        try:
            payload = engine.status(conn, switch_id, now)
        except KeyError:
            continue
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_checkin(args) -> int:
    cfg, conn = _load(args)
    switch_id = _resolve(conn, args)
    now = int(time.time())
    nonce = liveness.new_nonce()
    token = liveness.sign_device(args.secret, switch_id, args.device, now, nonce)
    result = liveness.checkin(conn, cfg.audit_key, switch_id, args.device, now, nonce, token, now)
    print(f"check-in registado: device={result.device_id} at={result.at}")
    return 0


def cmd_cancel(args) -> int:
    cfg, conn = _load(args)
    switch_id = _resolve(conn, args)
    now = int(time.time())
    nonce = liveness.new_nonce()
    token = liveness.sign_owner(args.secret, switch_id, now, nonce)
    previous = liveness.cancel(conn, cfg.audit_key, switch_id, now, nonce, token, now)
    print(f"cancelado: {previous} -> ok")
    return 0


def cmd_tick(args) -> int:
    cfg, conn = _load(args)
    transport = deliver.build_transport(cfg)
    now = int(args.now) if args.now else int(time.time())
    summary = runner.run_tick(conn, cfg.audit_key, cfg, transport, now)
    print(runner.render(summary))
    return 0


def cmd_worker(args) -> int:
    cfg, conn = _load(args)
    transport = deliver.build_transport(cfg)
    interval = cfg.server.tick_seconds
    print(f"worker a correr: tick cada {interval}s, ctrl-c para parar", flush=True)
    while True:
        started = time.time()
        try:
            summary = runner.run_tick(conn, cfg.audit_key, cfg, transport, int(started))
            changed = [s["switch"] + "=" + s["state"] for s in summary["switches"]]
            print(f"[{int(started)}] {' '.join(changed) or 'sem mudancas'}", flush=True)
        except Exception as exc:  # noqa: BLE001 - a dead worker is the worst failure mode
            print(f"[{int(started)}] tick falhou: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        time.sleep(max(1, interval - (time.time() - started)))


def cmd_serve(args) -> int:
    from . import server as server_mod

    cfg, conn = _load(args)
    httpd = server_mod.serve(cfg, conn, cfg.audit_key, verbose=args.verbose)
    print(f"a servir em http://{cfg.server.host}:{cfg.server.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("parado")
    finally:
        httpd.server_close()
    return 0


def cmd_verify(args) -> int:
    cfg, conn = _load(args)
    ok, count, bad, reason = audit.verify(conn, cfg.audit_key)
    print(f"cadeia de auditoria: {'INTACTA' if ok else 'COMPROMETIDA'}")
    print(f"entradas           : {count}")
    print(f"chave              : {audit.key_fingerprint(cfg.audit_key)}")
    if not ok:
        print(f"primeira entrada errada: seq {bad} ({reason})")
    return 0 if ok else 1


def cmd_export_audit(args) -> int:
    cfg, conn = _load(args)
    payload = audit.export(conn, cfg.audit_key)
    if args.out:
        Path(args.out).write_text(payload + "\n")
        print(f"exportado para {args.out}")
    else:
        print(payload)
    return 0


# --- selftest ------------------------------------------------------------


def cmd_selftest(args) -> int:
    ok = True
    print("1/4 auditoria")
    ok &= _selftest_audit()

    print("2/4 round-trip GnuPG")
    ok &= _selftest_gpg()

    print("3/4 invariantes do motor")
    ok &= _selftest_engine()

    print("4/4 suite de testes")
    import unittest

    root = Path(__file__).parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(root / "tests"), top_level_dir=str(root)
    )
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    ok &= result.wasSuccessful()

    print()
    print("SELFTEST OK" if ok else "SELFTEST FALHOU")
    return 0 if ok else 1


def _selftest_audit() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.sqlite3")
        key = config_mod.new_audit_key()
        for i in range(5):
            audit.append(conn, key, 1000 + i, "test", {"i": i})
        good, count, _, _ = audit.verify(conn, key)
        conn.execute("UPDATE audit_log SET detail=? WHERE seq=3", ('{"i":999}',))
        bad, _, where, why = audit.verify(conn, key)
        print(f"   intacta={good} entradas={count} adulterada_detectada={not bad} em seq {where}")
        return good and not bad


def _selftest_gpg() -> bool:
    if not shutil_which("gpg"):
        print("   gpg ausente, ignorado")
        return True
    home = Path(tempfile.mkdtemp())
    env_backup = os.environ.get("GNUPGHOME")
    os.environ["GNUPGHOME"] = str(home)
    os.chmod(home, 0o700)
    try:
        import subprocess

        gen = subprocess.run(
            ["gpg", "--batch", "--quiet", "--passphrase", "", "--quick-generate-key",
             "dmks selftest <selftest@invalid>", "default", "default", "never"],
            capture_output=True,
        )
        if gen.returncode != 0:
            print(f"   nao foi possivel gerar chave de teste: {gen.stderr.decode()[:120]}")
            return False
        listing = seal.list_encryption_keys()
        if not listing:
            print("   nenhuma chave de teste encontrada")
            return False
        fingerprint = listing[0].fingerprint

        source = home / "evidencia.txt"
        source.write_text("evidencia de teste\n")
        output = home / "pacote.gpg"
        digest = seal.seal([source], [fingerprint], output)

        problems = seal.verify_container(output, digest, [fingerprint])
        print(f"   intacto={not problems} subchave_detectada={listing[0].subkey_keyids != ()}")

        tampered = home / " adulterado.gpg"
        data = bytearray(output.read_bytes())
        data[-1] ^= 0xFF
        tampered.write_bytes(bytes(data))
        tampered_problems = seal.verify_container(tampered, digest, [fingerprint])
        return not problems and bool(tampered_problems)
    finally:
        if env_backup is None:
            os.environ.pop("GNUPGHOME", None)
        else:
            os.environ["GNUPGHOME"] = env_backup
        import shutil

        shutil.rmtree(home, ignore_errors=True)


def _selftest_engine() -> bool:
    from .selftest_engine import run_invariants

    return run_invariants()


def shutil_which(name: str) -> str | None:
    from shutil import which

    return which(name)


# --- argument parsing ----------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dmks", description="dead man's kill switch")
    parser.add_argument("--data-dir", default=os.environ.get("DMKS_DATA_DIR", DEFAULT_DATA_DIR))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="cria data dir, config e switch inicial")
    p.add_argument("--switch", default="main")
    p.add_argument("--name", default="principal")
    p.add_argument("--warn-days", type=int, default=7)
    p.add_argument("--arm-days", type=int, default=14)
    p.add_argument("--release-days", type=int, default=30)
    p.add_argument("--release-mode", choices=config_mod.RELEASE_MODES, default="hold")
    p.add_argument("--owner-email")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8770)
    p.add_argument("--tick-seconds", type=int, default=3600)
    p.add_argument("--smtp-host")
    p.add_argument("--smtp-port", type=int, default=587)
    p.add_argument("--smtp-from")
    p.add_argument("--webhook-url")
    p.add_argument("--publish-dir")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("enroll", help="enrola um dispositivo e imprime o secret")
    p.add_argument("--switch")
    p.add_argument("--device", required=True)
    p.add_argument("--label", default="")
    p.add_argument("--secret", help="secret gerado no dispositivo; nunca passa pelo servidor")
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("retire", help="retira um dispositivo")
    p.add_argument("--device", required=True)
    p.set_defaults(func=cmd_retire)

    p = sub.add_parser("devices", help="lista dispositivos")
    p.add_argument("--switch")
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("recipient", help=" gere destinatarios")
    p.add_argument("action", choices=("add", "remove"))
    p.add_argument("--switch")
    p.add_argument("--address")
    p.add_argument("--gpg", help="fingerprint da chave publica de cifragem")
    p.add_argument("--webhook")
    p.add_argument("--owner", action="store_true", help="este destinatario e o dono")
    p.set_defaults(func=cmd_recipient)

    p = sub.add_parser("seal", help="cifra evidencias para os destinatarios")
    p.add_argument("--switch")
    p.add_argument("--note", default=None)
    p.add_argument("files", nargs="+")
    p.set_defaults(func=cmd_seal)

    p = sub.add_parser("packets", help="lista pacotes selados")
    p.add_argument("--switch")
    p.set_defaults(func=cmd_packets)

    p = sub.add_parser("arm", help="ajusta parametros do switch")
    p.add_argument("--switch")
    p.add_argument("--release-mode", choices=config_mod.RELEASE_MODES)
    p.add_argument("--release-days", type=int)
    p.add_argument("--confirmations", type=int)
    p.set_defaults(func=cmd_arm)

    p = sub.add_parser("status", help="estado actual")
    p.add_argument("--switch")
    p.add_argument("--now", type=int, help="epoch para simular (util em testes)")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("checkin", help="faz check-in a partir deste dispositivo")
    p.add_argument("--switch")
    p.add_argument("--device", required=True)
    p.add_argument("--secret", required=True)
    p.set_defaults(func=cmd_checkin)

    p = sub.add_parser("cancel", help="cancela a escalacao com o secret do dono")
    p.add_argument("--switch")
    p.add_argument("--secret", required=True)
    p.set_defaults(func=cmd_cancel)

    p = sub.add_parser("tick", help="corre uma avaliacao e sai")
    p.add_argument("--now", type=int, help="epoch para simular (util em testes)")
    p.set_defaults(func=cmd_tick)

    p = sub.add_parser("worker", help="loop de avaliacao")
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("serve", help="servidor HTTP")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("verify", help="verifica a cadeia de auditoria")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("export-audit", help="exporta a auditoria")
    p.add_argument("--out")
    p.set_defaults(func=cmd_export_audit)

    p = sub.add_parser("selftest", help="verificacao completa do sistema")
    p.set_defaults(func=cmd_selftest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())