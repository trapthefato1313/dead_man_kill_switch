# Deploy da malha de nós dmks (SMTP sobre WireGuard)

Como pôr **N hosts independentes** a guardar cópias do pacote selado, e o switch a
fazer fan-out para todos. Este é o passo que transforma "300 sockets no mesmo host"
(que não é independência) em **hosts separados com falhas separadas**.

| Marca | Significado |
|---|---|
| **[EXISTE]** | implementado e testado neste repositório |
| **[PLANO]** | desenho, ainda por implementar |

## Porquê WireGuard (e não SMTP público)

O `dmks sink` **[EXISTE]** é um *store*, não um relay: grava cada mensagem com recibo
(`.eml` + SHA-256 + `receipts.jsonl`). Duas consequências obrigam à malha:

1. **Não tem STARTTLS.** Exposto na internet, o conteúdo viaja em claro.
2. **É um coletor.** Um sink público vira depósito de spam de qualquer bot.

A malha resolve ambos: o sink ouve **só no IP do túnel** (ex.: `10.66.0.11:2525`) e o
WireGuard cifra tudo entre os hosts. Não há porta SMTP aberta à internet.

```
        internet
           |
   [ hub: 10.66.0.1 ]  <- corre também o switch (controlador)
     /            \
[no-001]        [no-002]   (+ N nós)
10.66.0.11      10.66.0.12
sink:2525       sink:2525
```

## Limites honestos

- **Independência** vem de **hosts separados** (operadores/IPs distintos). N nós na
  mesma máquina não são independência.
- **Hub-and-spoke** tem um ponto central (o hub). Para remover isso é preciso malha
  completa (O(n²) pares) — o `generate.py` faz hub-spoke; malha completa é **[PLANO]**.
- Isto dá **redundância/cofres**, **não** deliverability para Gmail/Outlook. Entrega
  externa continua a exigir reputação (ver `deploy/sovereign-mail/`).

---

## 1. Preparar o inventário **[EXISTE]**

```bash
cd deploy/mesh
cp inventory.example.toml inventory.toml
$EDITOR inventory.toml
```

Preenche: `[hub]` (endpoint público, IP na malha), um `[[node]]` por host
(`public_host`, `address` na malha) e `[sender].from`.

Chaves: deixa `generate_keys = true` se tiveres o `wg` (wireguard-tools) na tua
máquina — o gerador cria as chaves todas. Senão põe `false` e preenche
`public_key`/`private_key` à mão (usa `wg genkey`/`wg pubkey` em cada host).

## 2. Gerar os bundles **[EXISTE]**

```bash
python3 generate.py            # escreve tudo em out/
```

Produz:
- `out/wg/hub.conf` — config WireGuard do hub
- `out/wg/<nome>.conf` + `out/wg/keys/<nome>.key` — por nó (chave privada, modo 600)
- `out/node/<nome>/` — bundle autossuficiente (wg0.conf, `dmks/`, unit, instalador)
- `out/dmks/smtp_servers.json` — fragmento para o `config.json` do switch
- `out/push.sh` — scp dos bundles

> Trata `out/wg/keys/` e os bundles como segredos. Apaga-os depois de instalar.

## 3. Hub (host do switch) **[EXISTE]**

```bash
sudo install -m600 out/wg/hub.conf /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
sudo sysctl -w net.ipv4.ip_forward=1     # já está no PostUp
```

O switch corre neste hub. (Se correr noutro host, junta-o à malha como mais um nó.)

## 4. Nós **[EXISTE]**

```bash
bash out/push.sh                          # ou copia out/node/<nome> à mão
for h in 203.0.113.10 203.0.113.11; do
  ssh root@$h 'cd /tmp/dmks-<nome> && ./install-node.sh'
done
```

O `install-node.sh` é idempotente: instala `wireguard-tools`+`python3`, sobe o
`wg-quick@wg0`, copia o código para `/opt/dmks`, cria o utilizador `dmks`, instala e
arranca `dmks-sink.service`.

## 5. Verificar **[EXISTE]**

```bash
ping -c1 10.66.0.11                       # do hub
nc -vz 10.66.0.11 2525                    # sink a ouvir
```

## 6. Ligar ao switch **[EXISTE]**

Faz merge do fragmento na secção `server` do `<data-dir>/config.json`:

```bash
python3 - <<'PY'
import json
cfg = json.load(open("$DMKS_DATA/config.json"))
frag = json.load(open("out/dmks/smtp_servers.json"))
cfg["server"].update(frag)                # smtp_strategy=fanout + smtp_servers
json.dump(cfg, open("$DMKS_DATA/config.json","w"), indent=2)
PY
```

**`fanout`** é o correto aqui: cada nó guarda a sua cópia e o destinatário só conta
como entregue quando **todos** confirmaram (é o que dá a redundância). Não uses
`failover` — isso é para relays reais.

## 7. Testar o disparo para a malha **[EXISTE]**

```bash
python3 scripts/demo_first_shot.py        # demonstra a escalada + entrega
```

Ou, na instância real, avança o relógio em incrementos ≤ `max_credit` (3 dias) até
`released`, e confirma que **cada** nó em `10.66.0.x` tem o `.eml` e o recibo:

```bash
ls /var/lib/dmks-sink/spool/*.eml         # em cada nó
tail -n1 /var/lib/dmks-sink/spool/receipts.jsonl
```

## Roadmap (camadas P2P) **[PLANO]**

Malha completa, identidade Ed25519 por nó, descoberta DHT, TLS/HPKE ponta-a-ponta e o
cliente de **recuperação** (o destinatário ir buscar o pacote a qualquer nó) estão em
`docs/p2p-mail/`. Este kit cobre a **camada C (transporte/cofres)** com o protótipo
Python que já existe e corre.
