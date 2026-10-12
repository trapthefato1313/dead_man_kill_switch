# PROTOCOL.md — Especificação do protocolo de rede MailNet P2P

Estado: **rascunho v0** (`[PLANO]`, salvo onde marcado `[EXISTE]`). Objetivo: permitir **duas
implementações independentes** interoperarem. Tudo o que não estiver aqui é implícito e
portanto não vinculativo.

Convenções: `H()` = SHA-256; assinaturas = Ed25519 (RFC 8032); codificação de rede =
canonical CBOR ou protobuf com esquema versionado; todos os identificadores com prefixo de
versão `v0.`.

---

## 1. Camada A — Identidade dos nós

### 1.1 Par de chaves
Cada nó gera um par **Ed25519**. A chave privada nunca sai do host (ver `SECURITY.md §4`).

```
node_id = H(pubkey)          # 32 bytes; identifica o nó e o seu lugar na DHT
```

### 1.2 Autenticação mútua
- Handshake **TLS 1.3** com certificado **auto-assinado**; a verificação é por **pinning de
  SPKI** contra o `node_id` esperado (não por CA pública).
- Alternativa/overlay: **Noise IK** ou **WireGuard** entre operadores que se conhecem.
- O `node_id` apresentado no handshake **tem de** corresponder ao registo assinado (1.4).

### 1.3 Rotação e revogação
- **Rotação:** o registo de nó inclui `valid_until` e pode ser re-assinado pela **chave de
  longa duração** do operador (`operator_key`), diferente da chave de sessão do nó.
- **Revogação:** publicado um `Revocation(node_id, reason, sig_operator, timestamp)` na DHT
  com TTL longo. Nós que vejam um `node_id` revogado recusam novas sessões.

### 1.4 Anti-Sybil
- Custo de entrada **técnico e verificável**, não comercial:
  - **Prova de trabalho** ou **prova de tempo** no registo (ajustável, barata de verificar).
  - **Peso de reputação** inicial baixo; só sobe com entregas confirmadas por recibos.
- **Não** existe lista de autorização comercial obrigatória (requisito do pedido).
- **`[NÃO PROMETIDO]`** Nenhuma defesa elimina Sybil; encarece-o e limita o dano.

---

## 2. Camada B — Descoberta descentralizada

### 2.1 DHT tipo Kademlia
- Espaço de chaves = `node_id` (32 bytes). *k*-buckets, `k` configurável (ex.: 20).
- Cada nó guarda registos da sua vizinhança; não há diretório central.
- **Endurecimento S/Kademlia-style:** IDs gerados com PoW vinculado à chave, lookups
  disjuntas em paralelo, e limites de taxa por par.

### 2.2 Registo de nó (assinado)
```
NodeRecord {
  version: "v0."
  node_id:  H(pubkey)
  pubkey:   ed25519
  operator_key: ed25519        # chave de longa duração, para rotação/revogação
  endpoints: [ {proto:"tls", host, port}, {proto:"smtp", host, port} ]
  caps:      { relay: bool, storage_bytes: u64, smtp_mx: bool }
  valid_until: u64             # epoch
  pow:         bytes           # prova de trabalho vinculada a node_id
  sig:         ed25519(pubkey) # assinatura de todos os campos acima
}
```

### 2.3 Bootstrap sem ponto único
Múltiplas vias, todas opcionais e substituíveis:
- **DNS TXT** de vários domínios independentes com endereços de *seeds*.
- **Lista de seeds estática** empacotada com o software (atualizável).
- **Peer exchange**: qualquer nó devolve vizinhos vivos (com verificação de assinatura).

Perder qualquer seed **não** derruba a rede: os pares vivos mantêm-se.

### 2.4 Reputação e mitigação
- Pontuação local e não global (evita autoridade central de reputação): submetida por
  **recibos verificáveis** (§4.4) e por *attestations* assinadas.
- Nós com mau comportamento são **depriorizados** localmente (throttling, menos
  vizinhos), não banidos globalmente.
- **NAT:** suportámos buraco de NAT quando possível (hole punching) e *relays* como
  fallback, **sem prometer** conectividade universal — o pedido exige isso explicitamente.

---

## 3. Camada C — Transporte de mensagens

### 3.1 Dois planos
- **Plano externo:** SMTP convencional (RFC 5321) para entrar/sair do mundo real.
- **Plano interno:** protocolo de relay entre nós (store-and-forward + recibos), sobre TLS.

### 3.2 Fila persistente (ver §6)
Cada mensagem é atómica e durável antes de ser reconhecida (`250`/`ACK`).

### 3.3 Retentativas e duplicados
- Política exponencial com limite (ex.: 5 tentativas, backoff 1m..8h, TTL da fila 72h).
- **Dedup:** chave = `H(message_id || content_hash)`. A mesma mensagem entregue duas vezes
  produz **um** recibo lógico (`exactly-once` observável). `[EXISTE]` no protótipo: a
  release reenviava só ao canal falhado, sem duplicar entregas bem-sucedidas.

### 3.4 Anti-open-relay
- Rejeitar `RCPT` para destinos fora das políticas autorizadas do nó.
- Autenticação obrigatória para submissão; relay aberto é proibido por desenho.
- Limites por remetente, por destino e por janela temporal.

---

## 4. Formato da mensagem e recibo

### 4.1 Envelope
```
Envelope {
  version:"v0."
  msg_id:      uuid                  # estável
  ts:          u64
  from:        addr
  to:          [addr]
  origin_node: node_id
  path:        [node_id]             # trace, cada salto assina
  payload_ct:  bytes                 # conteúdo cifrado (HPKE) ou MIME claro
  content_hash:H(payload_ct)
  sig_origin:  ed25519
}
```

### 4.2 Confidencialidade
- **HPKE** ponta-a-ponta quando o destinatário publica chave de cifra.
- Caso contrário, TLS ponto-a-ponto; o conteúdo fica legível para relays — **declarado**,
  não escondido.

### 4.3 Interoperabilidade SMTP
- Na fronteira: `Message-ID`, `Date`, `From`, `To`, `Subject`, corpo MIME; alinhamento
  SPF/DKIM/DMARC (ver `SECURITY.md §3`).

### 4.4 Recibo (prova de entrega)
```
Receipt {
  version:"v0."
  msg_id:     uuid
  node_id:    node_id             # nó que recebeu
  ts:         u64
  size:       u64
  content_hash:H(payload_ct)      # vincula o recibo ao conteúdo
  peer:       addr                # quem entregou
  sig_node:   ed25519
}
```
Um `Receipt` assinado é a **única** prova aceite de que um nó guardou a mensagem.
`[EXISTE]` no protótipo: ficheiro `.eml` com permissões `600` + linha em `receipts.jsonl`.

---

## 5. Camada D — Governança permissionless

- **Regras públicas e verificáveis** em `spec/`, versionadas, com histórico git assinado.
- **Participação aberta** a quem cumprir os requisitos **técnicos** (identidade, PoW,
  TLS, políticas anti-abuso). Sem autorização comercial.
- **Processo de propostas:** documento de proposta → revisão pública → período de
  compatibilidade (dois formatos coexistindo) → versão. *Feature flags* por versão.
- **Rollback de protocolo:** cada versão declara como reverter para a anterior.
- **`[NÃO PROMETIDO]`** Governança aberta **não** garante ausência de conflitos nem de
  captura por maioria; mitiga-se com publicidade e reprodutibilidade, não se elimina.

---

## 6. Armazenamento e filas

### 6.1 Layout por nó
```
/var/lib/mailnet/
├── queue/
│   ├── incoming/     # recebidas, à espera de encaminhar
│   ├── deferred/     # retentativas pendentes
│   ├── active/       # em processamento
│   └── corrupt/      # quarentena (nunca apagar silenciosamente)
├── spool/            # mensagens guardadas/entregues (modo sink)  [EXISTE]
│   ├── <ts>-<seq>.eml        # chmod 600
│   └── receipts.jsonl        # recibo por linha, append-only
├── meta.sqlite      # índices: msg_id, hashes, tentativas, TTL (WAL)
└── keys/            # chaves Ed25519 (permissões estritas)
```

### 6.2 Regras
- **Append-only** para recibos (auditoria); `fsync` antes de ACK.
- **Nunca** colocar dados/estado na store Nix (`/nix/store` é imutável).
- **Quarentena** em vez de eliminação: uma mensagem suspeita vai para `corrupt/` com motivo.
- Sharding por data sob volume; SQLite por partição para evitar um único ficheiro gigante.
- **`[POR MEDIR]`** IOPS e latência de `fsync` por mensagem são o limite prático de cada
  nó — medir antes de afirmar capacidade (§`ECONOMICS.md §5`).
