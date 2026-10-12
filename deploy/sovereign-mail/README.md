# Infraestrutura Soberana de E-mail — bundle de implantação

Guia do documento único, transformado em ficheiros implantáveis. Stack:

**Listmonk** (campanhas, VPS 0) + **3 nós Stalwart** (envio, VPS 1–3) + **domínio próprio** (reputação).

> **Aviso de consentimento (obrigatório):** isto serve para correio **opt-in**. Não uses listas
> compradas, raspadas ou importadas sem re-confirmação. O aquecimento (warm-up) existe para
> proteger a reputação, **não** para fugir a filtros. Enviar não solicitado é spam e queima
> os IPs — e é o que este desenho evita.

Estado: **pronto a implantar** (templates + `render.sh`). Não testado neste ambiente (aqui não há Docker).

---

## Estrutura

```
deploy/sovereign-mail/
├── .env.example                     # todas as variáveis (placeholders)
├── render.sh                        # gera os ficheiros em out/
├── templates/
│   ├── listmonk-compose.yml.tmpl
│   ├── listmonk.config.toml.tmpl
│   ├── stalwart-compose.yml.tmpl
│   └── dns-records.txt.tmpl
├── warmup.md                        # cronograma de 8 semanas
└── README.md                        # este ficheiro
```

## Arquitetura

```
                    ┌─ Nó 1 (VPS A): Stalwart ── mx.DOMINIO
Listmonk (VPS 0) ───┼─ Nó 2 (VPS B): Stalwart ── mx2.DOMINIO
                    └─ Nó 3 (VPS C): Stalwart ── mx3.DOMINIO
```

- **VPS 0**: Listmonk (painel, listas, campanhas). 1 vCPU / 1 GB chega.
- **Nós 1–3**: MTAs de envio. Cada um precisa de **IP dedicado limpo** e **porta 25 liberada**
  (OVH, Contabo, BuyVM costumam liberar; Hetzner/Vultr por pedido).

---

## Passo 0 — Configurar variáveis

```bash
cd deploy/sovereign-mail
cp .env.example .env
$EDITOR .env          # preenche DOMINIO, os 3 IPs e as passwords
```

## Passo 1 — Gerar os ficheiros

```bash
./render.sh           # escreve tudo em out/
```

## Passo 2 — Listmonk (VPS 0)

```bash
scp -r out/listmonk/ root@VPS0:/opt/listmonk/
ssh root@VPS0 'cd /opt/listmonk && mkdir -p uploads && \
  docker compose run --rm listmonk ./listmonk --install --config config.toml && \
  docker compose up -d'
```
Painel em `http://IP_VPS0:9000`. Em **Settings → SMTP**, cadastra os 3 nós (host `mx/mx2/mx3.DOMINIO:587`,
com o utilizador/senha criado no Stalwart de cada um). Em **Settings → Bounces**, aponta para a caixa
IMAP de cada nó (ou webhook).

## Passo 3 — Nós Stalwart (VPS 1, 2 e 3)

> **Stalwart v0.16+**: a imagem é `stalwartlabs/stalwart` (não `mail-server`). A configuração vive na
> base de dados (`/var/lib/stalwart`); o `/etc/stalwart` só guarda o `config.json` do datastore. No 1.º
> arranque não há config: o servidor entra em **modo bootstrap** e serve o *wizard* em
> `http://IP_DO_NO:8080/admin` (credencial: `STALWART_RECOVERY_ADMIN` do `.env`). Sem wizard, dá-se o
> setup não-interativo com `config.json` + `stalwart-cli` (vê a doc oficial).

Em **cada** nó, copia `out/stalwart/` e ajusta `NODE_HOSTNAME` (mx / mx2 / mx3):

```bash
scp -r out/stalwart/ root@VPS1:/opt/stalwart/
ssh root@VPS1 'cd /opt/stalwart && docker compose up -d && docker compose logs | grep -i password'
```

Abre `http://IP_DO_NO:8080/admin` (restringe por firewall ao teu IP) e segue o wizard:
1. **Server hostname**: `mx.DOMINIO` (nó 1) — tem de resolver para o IP do nó.
2. **Default domain**: `news.DOMINIO`.
3. **Storage/Account directory**: deixa os defaults (directório interno).
4. No fim, aponta o **admin** criado. Em **Management › Domains › (news.DOMINIO) › View DNS Zone
   file** tens o bloco DNS pronto a colar (inclui DKIM).
5. Em **Management › Domains**, define o **selector DKIM único por nó** (**sel1 / sel2 / sel3**).
6. Em **Management › Accounts**, cria a conta SMTP que o Listmonk e o switch usam (ex.: `relay@DOMINIO`).

Repete nos 3. O selector DKIM **tem de ser único por nó**.

> O `:8080` deixa de servir administração depois do wizard (passa a `https://NODE_HOSTNAME/admin`).
> Assim que o admin definitivo existir, **remove `STALWART_RECOVERY_ADMIN`** do `.env` e do compose.

<details>
<summary>Setup não-interativo (automatizar os 3 nós)</summary>

Para fugir ao wizard, escreve um `config.json` que descreve só o datastore, arranca em **recovery
mode** (`STALWART_RECOVERY_MODE=1 STALWART_RECOVERY_ADMIN=admin:senha`) e aplica a configuração
com o `stalwart-cli` (`STALWART_URL=http://127.0.0.1:8080 stalwart-cli apply --file export.json`).
Ver `stalw.art/docs/installation/non-interactive` e `stalwartlabs/stalwart/UPGRADING/v0_16.md`.
</details>

## Passo 4 — DNS

Publica o conteúdo de `out/dns/records.txt` na zona do domínio: A (mx/mx2/mx3), **PTR/rDNS no painel
de cada VPS**, SPF (os 3 `ip4:`), DKIM (3 selectors), DMARC (`p=none` → depois `quarantine` → `reject`)
e MX de `news.DOMINIO` para os 3 nós (bounces).

Validação:
```bash
dig +short TXT news.DOMINIO
dig +short TXT _dmarc.news.DOMINIO
dig +short TXT sel1._domainkey.news.DOMINIO
dig -x IP_NO_1
```
Teste ponta a ponta em **mail-tester.com**: objetivo **10/10 a partir de cada nó** antes de qualquer campanha.

## Passo 5 — Warm-up

Segue `warmup.md` (8 semanas). Regras: começar só por quem abriu e-mail teu nos últimos 30 dias;
**parar** se reclamação > 0,1 % ou bounce > 2 %; nunca saltar degraus.

## Passo 6 — Legal e monitorização

- Unsubscribe em um clique (`List-Unsubscribe` / `List-Unsubscribe-Post` do Listmonk) + `{{ UnsubscribeURL }}` no template
- Remetente identificado + endereço físico no rodapé (LGPD) + **double opt-in**
- Google Postmaster Tools, Microsoft SNDS, MXToolbox (blocklists), métricas do Listmonk (bounce < 2 %, reclamação < 0,1 %)

## Checklist antes do 1.º envio

- [ ] rDNS dos 3 IPs ⇄ mx/mx2/mx3 (PTR ↔ A)
- [ ] SPF, DKIM (3 selectors), DMARC publicados e a validar
- [ ] mail-tester.com = 10/10 de cada nó
- [ ] Lista limpa em validador
- [ ] Unsubscribe em um clique testado de verdade
- [ ] Postmaster Tools verificado
- [ ] Warm-up na agenda

---

## Ligar ao dead man's switch

Os 3 nós Stalwart servem de **relay do disparo**: quando o switch liberta o dossier, o e-mail
(com o anexo `.gpg`) sai por um dos nós, autenticado no submissão (587) e assinado com DKIM.

O switch suporta duas estratégias de frota (`smtp_strategy`):

| Estratégia | Semântica | Usa quando |
|---|---|---|
| `fanout` (default) | **Todos** os nós recebem uma cópia; só conta entregue quando todos confirmam | Nós são cofres privados (não MTAs reais) |
| `failover` | Os nós são relays intermutáveis; **exatamente uma cópia** por destinatário, saltando nós mortos | Nós são MTAs reais do teu domínio (**este caso**) |

> Com MTAs reais, `fanout` **duplicaria** o e-mail ao destinatário (uma vez por nó). Por isso o
> `render.sh` gera o `init` já com `--smtp-strategy failover`.

### Passos

1. Termina os Passos 2–4 (nós a correr, DKIM por nó, SPF/DKIM/DMARC publicados, mail-tester 10/10).
2. Cria no Stalwart uma **conta SMTP** que o switch usa para autenticar (ex.: `relay@DOMINIO`).
3. Gera o comando de init (já feito pelo `render.sh`):

```bash
./render.sh
cat out/dmks/init.sh        # revê os nós/remetente
```

4. No **servidor do switch**, exporta a senha e corre:

```bash
export SWITCH_SMTP_PASS='senha-da-conta-stalwart'
bash out/dmks/init.sh
```

5. Segue com o setup normal do switch (a chave GPG é a do destinatário):

```bash
export DMKS_DATA=/var/lib/dmks
export GNUPGHOME=$DMKS_DATA/gnupg        # o worker TEM de ver este keyring
mkdir -p "$DMKS_DATA/gnupg"; chmod 700 "$DMKS_DATA/gnupg"

python3 -m dmks --data-dir "$DMKS_DATA" enroll --device portatil
python3 -m dmks --data-dir "$DMKS_DATA" recipient add --address jornalista@proton.me --gpg <FPR>
python3 -m dmks --data-dir "$DMKS_DATA" recipient add --address "$OWNER_EMAIL" --gpg <FPR> --owner
# importa a publica de cada destinatario para o KEYRING DO WORKER (nao basta ter o FPR)
gpg --import chaves/*.pub
python3 -m dmks --data-dir "$DMKS_DATA" seal --note "dossier" evidencia.pdf
python3 -m dmks --data-dir "$DMKS_DATA" checkin --device portatil --secret <secret>
# em producao: systemd (unidade incluida), nao `worker &`
cp dmks-worker.service /etc/systemd/system/
systemctl enable --now dmks-worker.service
python3 -m dmks --data-dir "$DMKS_DATA" serve
```

### Pontos de atenção

- **`SWITCH_FROM` tem de ser de `NEWS_HOST`** (o domínio que o Stalwart assina e que está no SPF);
  senão o SPF/DKIM falham e cai em spam.
- **A password vive em `env:SWITCH_SMTP_PASS`** — o `config.json` guarda a referência, não o segredo.
- **`GNUPGHOME` tem de apontar para o keyring com as chaves públicas dos destinatários.** O FPR em
  `recipient add` não chega: o `gpg` de verificação só vê o que está importado no seu próprio keyring.
  Sem isto, a entrega é **recusada** (`GnuPG ... no usable public key`) e o pacote nunca sai — já
  aconteceu num teste e é a causa #1 de "o switch disparou mas não chegou nada". A unidade
  `dmks-worker.service` já define `GNUPGHOME=/var/lib/dmks/gnupg`.
- **Um worker por switch**: se correres dois, ambos avaliam, mas a idempotência da entrega evita
  duplicados. Não uses o mesmo `--data-dir` em máquinas diferentes sem partilhar a DB.
- Verifica antes de confiar: `mail-tester.com` a 10/10 a partir de cada nó, e um disparo de teste
  (`tick --now` em incrementos) a chegar ao destinatário com o anexo.

### Teste real ponta-a-ponta (um comando)

`scripts/real_test.py` aponta o switch a um relay SMTP **verdadeiro** e dispara até `released`,
entregando o pacote selado ao destinatário e mostrando a resposta exata do servidor:

```bash
export DMKS_SMTP_PASS='senha-da-conta-stalwart'
python3 scripts/real_test.py \
    --to gsantos@binaryxz.com \
    --from "$SWITCH_FROM" \
    --smtp-host mx.SEUDOMINIO.COM --smtp-port 587 \
    --smtp-user 'conta@news.SEUDOMINIO.COM' --smtp-pass env:DMKS_SMTP_PASS
```

Se entregar, o assunto `[dead man's switch] ... pacote selado ...` aparece na caixa com o anexo
`.gpg`. Se falhar, imprime o erro (auth/TLS/relay denied). Para testar sem sair da máquina, usa
`--self-sink`; para cifrar para a tua chave real, usa `--pubkey a-minha-chave.pub`.

---

## Nota de coerência com o projeto

O `dead_man_kill_switch` fixa "Linux nativo, **sem Docker**" e Nix/NixOS. Este bundle usa Docker
(como o guia original). Se quiseres alinhar com o princípio do projeto, há um equivalente NixOS em
`deploy/nixos/` (módulo `services.mailnet`); o Stalwart e o Listmonk também têm pacotes Nix. Diz se
queres que eu escreva a variante NixOS destes 4 serviços.
