# SECURITY.md — Modelo de ameaças e controlos (MailNet P2P)

Estado: **rascunho v0**. Honestidade primeiro: **não** prometemos anonimato absoluto,
resistência total à censura nem invulnerabilidade. Descrevemos o que se defende e o que
**não** se defende.

---

## 1. Ativos a proteger

1. **Chaves privadas** de identidade dos nós e chaves de operador.
2. **Conteúdo das mensagens** (confidencialidade e integridade).
3. **Recibos** (prova de entrega; base da reputação).
4. **Disponibilidade** da rede (entrega atempada).
5. **Metadados** (quem fala com quem, quando, tamanho).
6. **Cadeia de auditoria** (registo de operações sensíveis).

---

## 2. Modelo de ameaças (advogado do diabo)

| Ameaça | Ator | Impacto | Mitigação | Estado |
|---|---|---|---|---|
| Nós Sybil em massa | abusador | envenenar DHT, isolar vítimas | PoW vinculado a chave, *k*-buckets, lookups disjuntas, reputação local | **[PLANO]** |
| Spam / correio não solicitado | abusador | reputação do domínio arruinada | submissão autenticada, listas opt-in, throttling, bounces | **[EXISTE]** parcial |
| Open relay acidental | operador descuidado | rede vira origem de spam | relay recusado por defeito; políticas explícitas | **[PLANO]** |
| Interceção no salto | rede/ISP | leitura de conteúdo | TLS 1.3 entre nós; HPKE ponta-a-ponta | **[PLANO]** |
| Falsificação de remetente | atacante | phishing | SPF/DKIM/DMARC na fronteira; assinatura de envelope no plano interno | **[PLANO]** |
| DoS volumétrico | atacante | indisponibilidade | limites por par/IP, backpressure, quotas por remetente | **[PLANO]** |
| Envenenamento de DHT | Sybil | descoberta degradada | registos assinados, verificação de PoW, múltiplas fontes de bootstrap | **[PLANO]** |
| Roubo de chave | atacante local | imitar nó | chaves fora da imagem, `0600`, `DynamicUser`, rotação/revogação | **[PLANO]** |
| Repúdio de receção | nó malicioso | negar prova | recibos assinados não repudiáveis | **[EXISTE]** conceito |
| Análise de tráfego | observador global | mapa social | **não defendido em v0** — ver §5 | **[NÃO PROMETIDO]** |
| Censura por bloqueio de IP/domínio | adversário de rede | perda parcial | múltiplos nós/endpoints; **sem** evasão abusiva | **[NÃO PROMETIDO]** |
| Compromisso de fornecimento (supply chain) | atacante | binário malicioso | builds reproduzíveis Nix, assinatura de releases, hash pinning | **[PLANO]** |

---

## 3. Autenticação, criptografia e entregabilidade

- **Identidade:** Ed25519; `node_id = H(pubkey)`; pinning de SPKI no TLS; rotação via chave
  de operador; revogação publicada.
- **Canal:** TLS 1.3 (sem downgrade); suites modernas; ALPN por versão de protocolo.
- **Ponta-a-ponta:** HPKE quando o destinatário publica chave; caso contrário confidencialidade
  termina no relay (declarado).
- **Entregabilidade (fronteira SMTP):**
  - **SPF** (RFC 7208), **DKIM** (RFC 6376, rotação de chave), **DMARC** (RFC 7489, p=quarantine
    ou reject quando a reputação o permitir), **TLS** e **DNS reverso** (PTR) corretos.
  - Gestão de **bounces** e reclamações (FBL quando disponível) e **descadastro**.
  - **Limites** por domínio, remetente e destino; respeito absoluto pelas quotas.
  - **[NÃO PROMETIDO]** Nada aqui contorna bloqueios, quotas ou reputação. Rotação abusiva
    de IPs é proibida por desenho e seria o fim do projeto.

---

## 4. Isolamento de privilégios e gestão de segredos

- Serviço corre como utilizador sem privilégios (`DynamicUser`/`User=mailnet`), sem `root`.
- Hardening systemd: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
  `NoNewPrivileges=true`, `RestrictAddressFamilies` limitado, `MemoryDenyWriteExecute`.
- Chaves em `/var/lib/mailnet/keys` com `0600`, dono o serviço; nunca no repo.
- Segredos de deploy via **agenix/sops-nix/systemd-creds**; nunca em imagens ou config.
- Diretório de dados montado com `noexec`.

---

## 5. Limites explícitos (o que NÃO protegemos)

- **Anonimato do remetente:** o protocolo transporta identidade e caminho (`path`). Não é um
  sistema de anonimato. Adicionar mixnets/onion é trabalho futuro e traz os seus próprios
  custos e riscos.
- **Metadados:** em v0, um observador do caminho vê origem, destino e tamanho. Não é
  defendido.
- **Resistência total à censura:** melhora com descentralização, mas um adversário que
  controle a rede física pode degradar seriamente a entrega.
- **Participantes maliciosos:** são mitigados e limitados, nunca eliminados.
- **Confidencialidade perante relay:** sem HPKE, relays legítimos veem o conteúdo.

---

## 6. Auditoria pública e resposta a incidentes

- **Auditoria:** código aberto, builds reprodutíveis, releases assinadas, `spec/` versionada
  com histórico assinado. Qualquer pessoa reconstrói os binários e compara hashes.
- **Incidentes (runbook):**
  1. Detetar (alertas de anomalia de envio, reclamações, nós mortos em massa).
  2. Conter (revogar `node_id`/chave, cortar relay afetado, throttling de emergência).
  3. Erradicar (corrigir, novos hashes, nova release assinada).
  4. Recuperar (redeploy por `nixos-rebuild switch`, restauro de filas a partir de maildir).
  5. Aprender (post-mortem público sem dados pessoais).
- **Dados pessoais:** princípio de minimização; retenção declarada; eliminação a pedido
  quando aplicável; recibos guardam hashes, não conteúdo, sempre que possível.
- **Recuperação:** filas e spool em `maildir` são copiáveis a frio; a cadeia de auditoria é
  append-only e replicável para fora do nó (requisito para sobreviver à perda do nó).

---

## 7. Cadeia de auditoria

- Registo append-only de operações sensíveis (registo/revogação de nó, alterações de política,
  releases). Cada entrada ligada à anterior por hash (Merkle/tamper-evident).
- Para sobreviver à **apreensão/morte** de um nó, a cadeia deve ser **replicada** para nós
  independentes — enquanto isso não existir, esta é uma falha real, não teórica.
