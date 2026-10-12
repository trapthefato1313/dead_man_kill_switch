#!/usr/bin/env python3
"""Gera a configuracao da malha WireGuard e o fragmento smtp_servers do switch.

Entrada : inventory.toml (ver inventory.example.toml)
Saida   : out/
            wg/hub.conf                 config WireGuard do hub
            wg/<nome>.conf              config WireGuard de cada no
            wg/keys/<nome>.key          chaves privadas (modo 600)
            node/<nome>/...             bundle a copiar para o host
            dmks/smtp_servers.json      fragmento para o config.json do switch
            push.sh                     scp de cada bundle para o host

Nao instala nada nem toca em hosts: so escreve ficheiros. O install-node.sh
corre depois em cada host.

Sem dependencias externas (tomllib e da stdlib, Python >= 3.11).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
NODE_DIR = HERE / "node"
REPO = HERE.parent.parent
DEFAULT_SINK_PORT = 2525


class ConfigError(Exception):
    pass


def have_wg() -> bool:
    return shutil.which("wg") is not None


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise ConfigError(f"{' '.join(cmd)} falhou: {result.stderr.strip()}")
    return result.stdout.strip()


def gen_key() -> tuple[str, str]:
    private = _run(["wg", "genkey"])
    result = subprocess.run(["wg", "pubkey"], input=private, capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        raise ConfigError("wg pubkey falhou")
    return private, result.stdout.strip()


def load_inventory(path: Path) -> dict:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    if "mesh" not in data or "hub" not in data:
        raise ConfigError("inventory precisa de [mesh] e [hub]")
    if not data.get("node"):
        raise ConfigError("inventory precisa de pelo menos um [[node]]")
    return data


def resolve_keys(inv: dict) -> dict:
    """Devolve {name: (private, public)} para o hub e todos os nos.

    Gera com `wg` quando pedido e disponivel; caso contrario exige chaves
    preenchidas no inventario.
    """
    generate = bool(inv["mesh"].get("generate_keys", False))
    wg_ok = have_wg()
    if generate and not wg_ok:
        print("aviso: generate_keys=true mas `wg` nao existe; uso as chaves do inventario",
              file=sys.stderr)

    keys: dict[str, tuple[str, str]] = {}
    entries = [("hub", inv["hub"])] + [(n["name"], n) for n in inv["node"]]
    for name, entry in entries:
        private = (entry.get("private_key") or "").strip()
        public = (entry.get("public_key") or "").strip()
        if generate and wg_ok:
            private, public = gen_key()
        elif not (private and public):
            raise ConfigError(
                f"chaves em falta para {name!r}: instala `wg` e usa generate_keys=true, "
                "ou preenche private_key/public_key no inventario"
            )
        keys[name] = (private, public)
    return keys


def hub_conf(inv: dict, keys: dict) -> str:
    mesh = inv["mesh"]
    hub = inv["hub"]
    priv, _ = keys["hub"]
    lines = [
        "[Interface]",
        f"Address = {hub['address']}",
        f"ListenPort = {int(mesh.get('wg_port', 51820))}",
        f"PrivateKey = {priv}",
        "SaveConfig = false",
        "# Encaminha entre nos (o switch no hub alcanca todos).",
        "PostUp = sysctl -w net.ipv4.ip_forward=1",
        "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT",
        "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT",
        "",
    ]
    for node in inv["node"]:
        _, pub = keys[node["name"]]
        lines += [
            "[Peer]",
            f"# {node['name']}",
            f"PublicKey = {pub}",
            f"AllowedIPs = {node['address']}",
            "",
        ]
    return "\n".join(lines)


def node_conf(inv: dict, keys: dict, node: dict) -> str:
    hub = inv["hub"]
    _, hub_pub = keys["hub"]
    priv, _ = keys[node["name"]]
    network = inv["mesh"]["network"]
    return "\n".join([
        "[Interface]",
        f"Address = {node['address']}",
        f"PrivateKey = {priv}",
        "",
        "[Peer]",
        f"PublicKey = {hub_pub}",
        f"Endpoint = {hub['endpoint']}",
        f"AllowedIPs = {network}",
        "PersistentKeepalive = 25",
        "",
    ])


def smtp_servers(inv: dict) -> dict:
    sender = inv.get("sender", {}).get("from", "switch@localhost")
    port = int(inv["mesh"].get("sink_port", DEFAULT_SINK_PORT))
    return {
        "smtp_strategy": "fanout",
        "smtp_servers": [
            {
                "name": node["name"],
                "host": node["address"].split("/")[0],
                "port": port,
                "from": sender,
                "starttls": False,
            }
            for node in inv["node"]
        ],
    }


def _copy_tree(src: Path, dst: Path) -> None:
    shutil.copytree(
        src, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__")
    )


def write_bundles(inv: dict, keys: dict, out: Path) -> None:
    sink_port = int(inv["mesh"].get("sink_port", DEFAULT_SINK_PORT))
    wg = out / "wg"
    (wg / "keys").mkdir(parents=True, exist_ok=True)
    (wg / "hub.conf").write_text(hub_conf(inv, keys))
    for name, (priv, _) in keys.items():
        keyfile = wg / "keys" / f"{name}.key"
        keyfile.write_text(priv + "\n")
        keyfile.chmod(0o600)

    for node in inv["node"]:
        bundle = out / "node" / node["name"]
        bundle.mkdir(parents=True, exist_ok=True)
        conf = wg / f"{node['name']}.conf"
        conf.write_text(node_conf(inv, keys, node))
        conf.chmod(0o600)
        shutil.copy(conf, bundle / "wg0.conf")

        # O bundle e autossuficiente: leva o codigo e a unit para o host.
        _copy_tree(REPO / "dmks", bundle / "dmks")
        for asset in ("install-node.sh", "dmks-sink.service"):
            if NODE_DIR.joinpath(asset).exists():
                shutil.copy(NODE_DIR / asset, bundle / asset)
        (bundle / "install-node.sh").chmod(0o755)

        env = "\n".join([
            f"NODE_NAME={node['name']}",
            f"WG_IP={node['address'].split('/')[0]}",
            "SPOOL=/var/lib/dmks-sink/spool",
            f"WG_PORT={int(inv['mesh'].get('wg_port', 51820))}",
            f"SINK_PORT={sink_port}",
            "",
        ])
        (bundle / "install.env").write_text(env)

    (out / "dmks").mkdir(parents=True, exist_ok=True)
    (out / "dmks" / "smtp_servers.json").write_text(
        json.dumps(smtp_servers(inv), indent=2) + "\n"
    )


def write_push_script(inv: dict, out: Path) -> None:
    lines = ["#!/usr/bin/env bash", "set -euo pipefail", "# scp dos bundles",
             'ssh_user="${SSH_USER:-root}"', 'here="$(cd "$(dirname "$0")" && pwd)"', ""]
    for node in inv["node"]:
        host = node["public_host"]
        lines.append(
            f'scp -r "$here/node/{node["name"]}" "${{ssh_user}}@{host}:/tmp/dmks-{node["name"]}"'
        )
    lines.append("")
    (out / "push.sh").write_text("\n".join(lines))
    (out / "push.sh").chmod(0o755)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", default=str(HERE / "inventory.toml"))
    parser.add_argument("--out", default=str(HERE / "out"))
    args = parser.parse_args(argv)

    inv_path = Path(args.inventory)
    if not inv_path.exists():
        print(f"erro: {inv_path} nao existe (copia inventory.example.toml)", file=sys.stderr)
        return 2
    inv = load_inventory(inv_path)
    keys = resolve_keys(inv)
    out = Path(args.out)
    write_bundles(inv, keys, out)
    write_push_script(inv, out)
    print(f"ok: {len(inv['node'])} nos gerados em {out}/")
    print("  out/wg/hub.conf              -> instala no hub")
    print("  out/node/<nome>/             -> copia para cada host e corre install-node.sh")
    print("  out/dmks/smtp_servers.json   -> merge na seccao 'server' do config.json do switch")
    print("  out/push.sh                  -> scp de todos os bundles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
