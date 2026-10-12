# MailNet P2P — infraestrutura de e-mail distribuída

Rascunho de engenharia **v0**. Este documento descreve um desenho, não uma capacidade já
demonstrada. Cada afirmação está marcada:

| Marca | Significado |
|---|---|
| **[EXISTE]** | já implementado e coberto por testes neste repositório |
| **[PLANO]** | desenho concreto, ainda por implementar |
| **[POR MEDIR]** | requer benchmark/validação; os números são estimativas com pressupostos explícitos |
| **[NÃO PROMETIDO]** | fora de âmbito ou fisicamente/economicamente impossível de garantir |

---

## 0. Reality check (ler primeiro)

O pedido fixa metas de **300 000 nós** e **10 000 000 de mensagens/dia** com **custo
próximo de zero**, permissionless e resistente à censura. Isto é uma **direção**, não um
estado atual. Três verdades que o desenho tem de respeitar:

1. **Custo zero não existe.** Há custos inevitáveis: nome de domínio, endereços IP/ASN com
   reputação, largura de banda, energia, armazenamento, **trabalho humano** (abuso, entrega,
   operação) e o custo do tratamento de spam. O que se pode minimizar é o custo *marginal
   por mensagem* quando há recursos voluntários e software livre.
2. **Deliverabilidade para provedores dominantes exige reputação.** Gmail, Outlook, etc.
   aceitam ou rejeitam por reputação de IP e domínio, SPF/DKIM/DMARC, volume e reclamações.
   Uma rede **permissionless e anónima** que envie em massa será tratada como spam. A via
   sustentável é: (a) correio **entre nós da rede**; (b) listas **opt-in e autorizadas**;
   (c) respeitar quotas e políticas. **[NÃO PROMETIDO]** Não existe — e não haverá —
   mecanismo para contornar bloqueios, quotas ou reputação por rotação abusiva de IPs.
3. **"Mensagens autorizadas" = destinatários que consentiram.** Spam e abuso são o **modo de
   falha dominante** e o principal custo operacional. O sistema é dimensionado para
   entregar mensagens legítimas (notificações, listas opt-in, correio pessoal/associativo),
   não para amplificar envio não solicitado.

> "300 000 identidades registadas" **não** equivalem a "300 000 nós ativos". Ver
> `ECONOMICS.md §4`: a fração ativa é que governa a carga por nó.

---

## 1. Arquitetura em camadas

```
                         +------------------------------------------+
   correio convencional  |   mundo SMTP externo (RFC 5321)          |
   <-------------------->|   MX, STARTTLS, DKIM, SPF, DMARC          |
                         +--------------------+---------------------+
                                              |  SMTP ingress/egress
                         +--------------------v---------------------+
   camada E (entrega)    |  E. Gateway de entregabilidade           |
                         |     assinatura DKIM, verificação DMARC,  |
                         |     throttling por domínio/destino,       |
                         |     gestão de bounces e descadastros      |
                         +--------------------+---------------------+
                                              |
                         +--------------------v---------------------+
   camada C (transporte) |  C. Transporte store-and-forward          |
                         |     filas persistentes, retentativas       |
                         |     limitadas, dedup por Message-ID+hash,  |
                         |     anti-open-relay                        |
                         +--------------------+---------------------+
                                              |
      +---------------------------------------+-------------------------------+
      |                                                                       |
+-----v------------------+                                   +----------------v-------+
| B. Descoberta P2P      |                                   | D. Governança           |
|    DHT assinada +      |<--------------------------------->|    regras públicas,     |
|    peer exchange,      |        propostas/versões           |    requisitos técnicos   |
|    reputação           |                                   |    sem gate comercial    |
+-----+------------------+                                   +-------------------------+
      |
+-----v------------------+
| A. Identidade dos nós  |
|    Ed25519, node_id =  |
|    H(pubkey), rotação, |
|    revogação, anti-Sybil|
+-----+------------------+
      |
+-----v--------------------------------------------------------------+
| F. Deploy imutável (NixOS): binários verificados por hash, systemd, |
|    dados persistentes separados, segredos fora da imagem, rollback  |
+--------------------------------------------------------------------+
```

Camadas A–F correspondem exatamente a A–F do pedido. Cada uma é um módulo separado, com
fronteira e contrato próprios, para poder ser substituída sem parar a rede.

---

## 2. Stack tecnológica (justificada)

| Componente | Escolha | Porquê | Estado |
|---|---|---|---|
| SO / deploy | **NixOS + flakes** | builds reproduzíveis, implantação declarativa, rollback atómico, artefatos por hash; nada de Docker como requisito | **[PLANO]** |
| Serviço | **systemd** | integração nativa, hardening (`ProtectSystem`, `DynamicUser`), credenciais via `systemd-creds`/agenix | **[PLANO]** |
| Daemon de relay | **Rust** | binário estático único (fácil de empacotar em Nix), segurança de memória, async maduro, sem runtime pesado | **[PLANO]** |
| Protótipo atual | **Python 3 + stdlib** | já existe e corre (`dmks sink`, `dmks fleet`); serve para validar protocolo antes de reescrever | **[EXISTE]** |
| Fila/estado | **maildir por fila + SQLite (WAL)** | maildir = ficheiro por mensagem, durável, inspecionável; SQLite indexa metadados e dedup | **[PLANO]** |
| Identidade | **Ed25519** (RFC 8032) | assinaturas curtas, rápidas, padrão | **[PLANO]** |
| Confidencialidade | **TLS 1.3** (RFC 8446) + **HPKE** (RFC 9180) | TLS entre nós com pinning de SPKI; HPKE para cifra ponta-a-ponta do pacote | **[PLANO]** |
| Descoberta | **DHT tipo Kademlia** com registos de nó assinados + *peer exchange* | descoberta sem diretório central; cada nó guarda uma partição | **[PLANO]** |
| Overlay opcional | **WireGuard** | mesh privado opcional entre operadores que se conhecem; não obrigatório | **[PLANO]** |
| Correio convencional | **SMTP (RFC 5321), MIME**, **SPF** (RFC 7208), **DKIM** (RFC 6376), **DMARC** (RFC 7489) | interoperabilidade com o mundo real | **[PLANO]** |
| Segredos | **agenix** ou **sops-nix** | segredos cifrados no repo, desencriptados só no host | **[PLANO]** |

**Não** dependemos de: API proprietária obrigatória, fornecedor único de nuvem, registry
comercial, ou contas pagas como pré-requisito de funcionamento. Nenhuma escolha acima
requer Docker.

**Rust vs Go:** Rust porque o binário único e a ausência de runtime simplificam o empacotamento
reprodutível e o hardening; Go seria aceitável (estática, simples) mas tem GC e binários
maiores. Decisão reversível enquanto só existir o protótipo Python.

---

## 3. Protótipo mínimo já existente **[EXISTE]**

A peça C (transporte store-and-forward para uma frota de nós independentes) já tem um
protótipo funcional, sem dependências:

```bash
# Um nó receptor numa máquina (o software para cada computador da rede):
python3 -m dmks sink --bind 127.0.0.1 --port 2525 --spool /var/lib/mailnet/node

# Subir N nós numa só máquina (laboratório; não é independência real):
python3 -m dmks fleet --count 300 --base-port 2525 --spool-root /tmp/fleet
```

O switch (aplicação que *usa* a rede) configura cada nó como canal independente e faz
fan-out para todos:

```json
{
  "server": {
    "smtp_from": "switch@dmks.invalid",
    "smtp_servers": [
      {"name": "casa",     "host": "10.0.0.11", "port": 25, "from": "a@exemplo.pt"},
      {"name": "garagem",  "host": "10.0.0.12", "port": 25, "from": "a@exemplo.pt"}
    ]
  }
}
```

Propriedades já testadas (`tests/test_fleet.py`, 129 testes no total): conversa SMTP real
por socket, fan-out para todos os nós, **um nó morto não mata os restantes**, *exactly-once*
com retentativa só pelo canal que falhou, e recibo durável (ficheiro `.eml` + SHA-256 +
`receipts.jsonl`) por nó.

**Limite honesto:** correr 300 sinks no *mesmo host* prova o mecanismo à escala de sockets,
mas **não** é independência real — é o mesmo IP, o mesmo operador, a mesma falha. A
independência vem de **hosts separados**.

---

## 4. Estrutura dos repositórios **[PLANO]**

Monorepo inicial (fácil de auditar e versionar em conjunto), com fronteiras que permitem
extrair componentes depois:

```
mailnet/
├── docs/                     # esta especificação
├── spec/                     # especificação do protocolo (RFC-style, versionada)
├── crates/
│   ├── identity/             # A. Ed25519, node_id, rotação, revogação
│   ├── discovery/            # B. DHT, registos assinados, reputação
│   ├── transport/            # C. filas, store-and-forward, dedup
│   ├── governance/           # D. regras públicas, verificação de propostas
│   ├── deliverability/       # E. DKIM/SPF/DMARC, throttling, bounces
│   └── mailnetd/             # binário principal (systemd)
├── proto/                    # ficheiros de definição do protocolo de rede
├── deploy/
│   ├── nixos/                # flake + módulos NixOS (config de referência)
│   └── examples/             # implantações nativas + rollback
├── tools/
│   ├── bench/                # benchmarks reproduzíveis
│   └── interop/              # testes de interoperabilidade SMTP
└── tests/                    # testes de integração entre operadores
```

Protótipo atual (Python) vive em `dmks/` e mantém-se como referência de comportamento até o
daemon Rust o substituir.

---

## 5. Deploy imutável **[PLANO]**

Ver `deploy/nixos/`. Princípios:

- **Config declarativa e imutável** (flake com `system` e `inputs` fixados por hash).
- **Artefatos por hash**: nada é executado sem corresponder a um hash publicado.
- **Atualização atómica + rollback**: `nixos-rebuild switch` muda a geração; `--rollback`
  volta à anterior; dados e filas **nunca** vivem na store Nix.
- **Segredos fora** de imagens e do código (agenix/sops-nix/systemd-creds).
- **Separação**: `/nix/store` (binários) · `/etc/mailnet` (config) · `/var/lib/mailnet`
  (dados/filas) · `/run` (efémero).

---

## 6. Roadmap e critérios objetivos

| Fase | Entrega | Critério de conclusão (objetivo) |
|---|---|---|
| 1 | Pesquisa e viabilidade | `ECONOMICS.md` com pressupostos e três cenários revistos por medição |
| 2 | Especificação pública | `PROTOCOL.md` versionado; duas implementações independentes possíveis |
| 3 | Protótipo 2+ operadores | dois hosts distintos trocam mensagem e recibo; `tests/` passa em CI |
| 4 | Interop SMTP + segurança + falhas | suíte de interop verde; modelo de ameaças com testes de abuso |
| 5 | Deploy nativo (sem Docker) | `nixos-rebuild switch` + `--rollback` demonstrados num host limpo |
| 6 | Piloto comunitário | métricas publicadas: msgs/dia, latência p95, taxa de falha, custo/nó |
| 7 | Expansão gradual | benchmark reproduzível sustenta o alvo de carga; auditoria do protocolo |
| 8 | Avaliação 300k nós | estudo com fração ativa medida; decisão go/no-go documentada |

**Regra do projeto:** não construir escala (7–8) antes de 3–6 estarem provados. A prioridade é
uma rede **aberta, verificável, interoperável e sustentável**, não declarar descentralização.

---

## 7. Entregáveis obrigatórios (índice)

| # | Entregável | Onde |
|---|---|---|
| 1 | Diagrama da arquitetura | este ficheiro, §1 |
| 2 | Especificação do protocolo P2P | `PROTOCOL.md` |
| 3 | Stack tecnológica justificada | este ficheiro, §2 |
| 4 | Identidade, descoberta, governança | `PROTOCOL.md` §2–§5 |
| 5 | Estrutura dos repositórios | este ficheiro, §4 |
| 6 | Configuração de referência NixOS | `deploy/nixos/` |
| 7 | Implantação nativa e rollback | `deploy/nixos/configuration.nix`, §5 |
| 8 | Armazenamento e filas | `PROTOCOL.md` §6 |
| 9 | Modelo de ameaças e controlos | `SECURITY.md` |
| 10 | Plano de benchmark e testes | `ECONOMICS.md` §5 |
| 11 | Recursos e custos por cenário | `ECONOMICS.md` |
| 12 | Roadmap com critérios | este ficheiro, §6 |
