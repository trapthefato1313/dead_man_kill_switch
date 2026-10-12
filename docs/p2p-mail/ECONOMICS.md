# ECONOMICS.md — Escala, recursos e custos (MailNet P2P)

Estado: **rascunho v0**. **Todos os números são estimativas [POR MEDIR]** com pressupostos
explícitos. O objetivo do documento é tornar a economia discutível, não declarar "custo zero".

> **Regra:** não assumimos créditos promocionais, contas múltiplas para contornar limites,
> nem *trials*. Serviços "gratuitos" entram apenas se as suas condições **permitirem** a
> finalidade; caso contrário contam como custo.

---

## 1. Custos inevitáveis (não há zero)

| Custo | Porque é inevitável | Ordem de grandeza |
|---|---|---|
| Nome de domínio | SPF/DKIM/DMARC exigem DNS que **tu** controlas | ~10–20 €/ano por domínio |
| IP/ASN com reputação | provedores dominantes avaliam reputação de IP | incluído em VPS/hosting, ou trabalho para construir |
| Largura de banda | tráfego de relay/storage cresce com volume | ver §4 |
| Energia | nós sempre-ligados | 5–20 W por máquina doméstica |
| Armazenamento | filas + retenção + replicação | ver §4 |
| **Trabalho humano** | abuso, entregabilidade, operação, suporte | **o maior custo real** a escala |
| Resposta legal/abuso | reclamações, remoção, cumprimento | função obrigatória de qualquer rede de e-mail |

O software livre remove **licenças**; **não** remove banda, energia, armazenamento, IP
reputado nem trabalho humano.

---

## 2. Pressupostos de dimensionamento

| Símbolo | Valor | Nota |
|---|---|---|
| Volume de pico | 10 000 000 msg/dia | objetivo do pedido |
| Média | 115,7 msg/s | `10e6 / 86400` |
| Fator de pico | 4× | picos acima da média **[POR MEDIR]** |
| Mensagem média | 80 KB | texto + cabeçalhos; anexos são cauda longa |
| Replicação interna R | 2 cópias | durabilidade; ajustável |
| Destinatários médios | 2 | |
| Retenção | 30 dias | |

---

## 3. Três cenários

### Cenário 1 — Protótipo de custo monetário mínimo
- **Hardware:** 1–3 máquinas (reutilizadas ou Raspberry Pi / mini-PC).
- **Software:** 100% aberto (NixOS + MailNet). Custo de licença: 0.
- **Monetário:** domínio ~10–20 €/ano + energia (~5–20 W × 24 h ≈ 4–18 kWh/mês) —
  tipicamente **< 60 €/ano** se o hardware já existir; **+3–6 €/mês por VPS** se usar nuvem.
- **Limite:** entrega para provedores dominantes em volume **não** é viável a esta escala sem
  reputação construída; serve para correio entre nós e listas pequenas.
- **Trabalho humano:** poucas horas/mês.

### Cenário 2 — Rede comunitária (recursos voluntários)
- **Nós:** V voluntários, cada um com o seu hardware/ligação. Descoberta P2P; sem diretório pago.
- **Infra partilhada mínima:** 2–3 *seeds* sempre-ligados (podem ser VPS baratos ou máquinas
  de voluntários), >1 domínio para diversidade de bootstrap.
- **Custos monetários:** domínio(s) + eventual VPS de estabilidade (**~5–20 €/mês** cada).
- **Energia/banda:** cedidas por cada operador (custo do voluntário, não central).
- **Armazenamento:** distribuído; cada nó cede `caps.storage_bytes`.
- **Trabalho humano:** moderação de abuso, suporte, releases — **cresce com o número de
  operadores**, não com a boa vontade.
- **Adequado a:** milhares a dezenas de milhares de mensagens/dia com boa vontade e regras
  claras.

### Cenário 3 — 300 000 nós (avaliação de viabilidade)
- **Não é somar 300 000 máquinas.** A camada P2P escala; o que **não** escala sozinho é:
  - **tier de relay bem ligado** (IPs reputados, sempre-ligados) — necessário para falar com o
    mundo SMTP real;
  - **observabilidade** (saber se a rede está viva);
  - **moderação de abuso**;
  - **gestão de chaves DKIM** e reputação por domínio;
  - **resposta legal**.
- **Estimativa (grosseira, [POR MEDIR]):** dezenas a ~200 relays sempre-ligados pagos
  (20–50 €/mês cada) ⇒ **~1 000–10 000 €/mês** só de infraestrutura garantida, **mais** equipa
  humana (a variável dominante).
- **Conclusão:** os *bytes* são o problema fácil; a **entrega, a reputação e o abuso** são o
  problema caro. "Custo ~0" só se sustenta como **marginal por mensagem** numa rede com
  recursos largamente doados.

---

## 4. Carga e capacidade (por cenário de fração ativa)

Ingress = `10e6 × 80 KB = 800 GB/dia`.
Tráfego total ≈ ingress (0,8) + replicação interna (1,6) + egress a destinatários (1,6) ≈ **4 TB/dia**.
Média ≈ **370 Mbps**; pico (4×) ≈ **1,5 Gbps**.

Armazenamento bruto = `800 GB/dia × 30 = 24 TB`; com R=2 ⇒ **48 TB**.

> **Por que 300 000 registados ≠ 300 000 ativos:** nós domésticos são intermitentes e muitos
> estão atrás de NAT. A carga por nó depende da **fração ativa** no instante, não do registo.

| Fração ativa | Nós ativos | Storage/nó (48 TB) | Banda média/nó (4 TB/dia) |
|---|---|---|---|
| 1 % | 3 000 | 16 GB | ~123 kbps |
| 5 % | 15 000 | 3,2 GB | ~25 kbps |
| 20 % | 60 000 | 0,8 GB | ~6 kbps |
| 100 % | 300 000 | 0,16 GB | ~1,3 kbps |

**Leitura:** a **largura de banda e o armazenamento por nó são modestos** — o que aperta é (a)
número de nós *online ao mesmo tempo* e (b) a **taxa de `fsync`/IOPS** e o **handshake TLS**
por segundo, não os GB. Medir antes de afirmar capacidade (§5).

---

## 5. Plano de benchmark e testes **[POR MEDIR]**

**Métricas por nó:** msg/s em relay, latência p50/p95/p99, latência de `fsync`, CPU %, RSS,
IOPS, taxa de handshakes TLS/s, custo de fan-out para N destinos, tempo de verificação de PoW.

**Testes (reproduzíveis, num CI):**
1. **Throughput single-node:** saturar um nó; encontrar o joelho (i.e., onde `fsync` domina).
2. **Fan-out N numa caixa:** já existe (`dmks fleet`, 300 nós); medir custo por canal.
3. **Interoperabilidade multi-host:** 2+ hosts distintos trocam mensagem e recibo (Fase 3).
4. **Injeção de falhas:** matar nó a meio da entrega → *retry* só no canal falhado, sem duplicar.
5. **Supressão de duplicados:** entregar a mesma mensagem 2× → 1 recibo lógico.
6. **Handshake TLS:** conexões/s com pinning de SPKI.
7. **DHT com churn:** latência de lookup sob entrada/saída de nós.
8. **Custo anti-Sybil:** tempo de gerar/verificar PoW a vários níveis de dificuldade.

**Reprodutibilidade:** correr em NixOS, hardware especificado, scripts versionados
(`tools/bench/`), resultados commitados. Sem medição publicada, nenhum número deste ficheiro
deve ser usado como capacidade garantida.

**Ferramentas base já disponíveis:** `tests/test_fleet.py` (sockets SMTP reais, fan-out,
retry, 20–300 nós). Falta `tools/bench/` e os testes multi-host.
