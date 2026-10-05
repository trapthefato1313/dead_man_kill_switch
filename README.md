# dead man's kill switch

Um farol de prova de vida. Se deixares de fazer check-in, um pacote de prova
cifrado com GnuPG é entregue a quem tu escolheres. O servidor nunca tem a chave
privada, portanto nunca vê o conteúdo.

Feito sem dependências: Python 3.11+ standard library e o `gpg` do sistema.

---

## O problema que este projecto tenta resolver

Um dead man's switch tem dois jeitos de falhar, e um deles mata-te:

**Falhar a disparar.** Morres e a prova fica num disco que morre com a máquina.
**Falhar sem razão.** Continuas vivo e o pacote sai na rua, porque o telemóvel
ficou sem rede no hospital. Isto é tão grave que quase todos os dead man's
switches reais falham por aqui, não por falha técnica.

Por isso quase tudo neste projecto existe para evitar falsos alarmes, e o
`release_mode` por omissão é `hold`: nada sai sem alguém o ter armado
conscientemente.

## Garantias

1. **Estado derivado do relógio, não de execuções.** Uma máquina que esteve
   desligada uma semana chega à conclusão certa no primeiro tick de volta. Nada
   depende de o worker ter corrido a horas.
2. **Relógio corroborado, e o tempo creditado é diferente do tempo observado.**
   Uma correcção de NTP, um bug de fuso ou um VM que acorda com o relógio
   adiantado não podem fazer o switch disparar sozinhos. A marca de água guarda
   o tempo **creditado**, nunca o observado: sem isso, um salto de dez anos
   num único tecto era aceites e o tecto seguinte creditava-o todo. Uma
   avaliação só credita `max_credit` (3 dias) sem confirmação externa, e num
   banco de dados novo o tempo é limitado à idade do próprio switch. Se os
   relógios discordarem, o switch **congela** — não escala, e avisa-te.
3. **Entrega exactamente uma vez.** A linha em `deliveries` é a chave de
   idempotência. Crash entre "estado = released" e "email enviado" é seguro: o
   tick seguinte reenvia. Crash depois do email é seguro: a linha já estava
   confirmada. Nunca duplica, nunca perde.
4. **Gatilho redundante.** Worker local **e** `POST /api/tick` a partir de um
   cron externo (ver `.github/workflows/tick.yml`). Se o servidor cair, ainda há
   quem avalie.
5. **Integridade do pacote verificada três vezes** antes de sair: SHA-256 igual
   ao registado no momento de selar, GnuPG ainda reconhece o contentor, e o
   contentor está endereçado às chaves que inscribiste. Se algo falha, o
   watchdog avisa-te **enquanto estás vivo** e a entrega é recusada.
6. **Watchdog do servidor.** A falha mais silenciosa de todas é o servidor
   parar: aí o switch nunca dispara e tu nunca sabes. O watchdog detecta
   lacunas de tick e avisa-te.
7. **Recomputação completa** do estado a partir da base de dados. Não há
   contadores que derivem.
8. **Auditoria à prova de adulteração.** Cada entrada encosta à anterior
   (HMAC-SHA256). Editar, apagar, reordenar ou forjar uma entrada quebra a
   cadeia a partir desse ponto, e `dmks verify` diz-te onde.

## Começar

```bash
git clone https://github.com/trapthefato1313/dead_man_kill_switch
cd dead_man_kill_switch
python3 -m dmks --data-dir data init \
    --name "prova de vida" \
    --owner-email "eu@exemplo.pt" \
    --release-mode hold
```

Isto imprime o `tick token`. Guarda-o.

Enrola um dispositivo por cada aparelho que usas. Gera o secret **no
aparelho** se conseguires, para nunca tocar no servidor:

```bash
python3 -m dmks --data-dir data enroll --device phone --label "telemovel"
# ou, com secret gerado no aparelho:
python3 -m dmks --data-dir data enroll --device phone --secret "$(pass show dmks/phone)"
```

O servidor guarda só `sha256` derivado. Um dump completo da base de dados não
deixa ninguém forjar check-ins.

### Destinatário e chave pública

O destinatário precisa de uma chave GnuPG **pública**:

```bash
gpg --keyserver keyserver.ubuntu.com --recv-keys 0xABCDEF0123456789
python3 -m dmks --data-dir data recipient add \
    --address "advogado@exemplo.pt" \
    --gpg 0xABCDEF0123456789
```

Importa a chave privada **apenas no computador do destinatário**. Nunca no
servidor, nunca num portátil que te possa ser roubado.

### Selar a prova

```bash
python3 -m dmks --data-dir data seal --note "comunicacoes de ameaca" \
    evidencias/relatorio.pdf mensagens/*.png
```

O pacote é cifrado, verificado, e registado na auditoria com o seu SHA-256.

**Guarda uma cópia do `.gpg` noutro sítio.** Se o servidor perder o disco depois
de ti, o pacote vai com ele. Isto é uma limitação real do desenho: o pacote tem
de existir em pelo menos dois lugares.

### Check-in

A partir de qualquer dispositivo enrolado:

```bash
python3 -m dmks --data-dir data checkin --device phone --secret "$DMKS_PHONE_SECRET"
```

Ou via HTTP, que é o que um telemóvel faz:

```bash
curl -X POST http://127.0.0.1:8770/api/checkin \
  -d '{"switch":"main","device":"phone","ts":1700000000,"nonce":"...","token":"..."}'
```

Coloca isto num cron local de hora a hora, ou num script que corre quando o
aparelho acorda. A frequência do check-in é a frequência a que o relógio do
switch é posto a zero.

### Running

```ini
# /etc/systemd/system/dmks.service
[Unit]
Description=dead man's kill switch
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/dead_man_kill_switch
ExecStart=/usr/bin/python3 -m dmks --data-dir /opt/dmks-data worker
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

E o `serve` para o check-in por HTTP, protegido por systemd ou por um proxy com
TLS. O `/api/tick` fica para o cron externo.

## Estados

| Estado | Quando | O que acontece |
|---|---|---|
| `ok` | check-in recente | nada |
| `warn` | 7 dias de silêncio | avisa-te a ti |
| `armed` | 14 dias | avisa-te a ti, todos os dias |
| `released` | 30 dias | entrega o pacote |

A subida de estado exige o quorum cumprido em **dois ticks consecutivos**.
Um tick anómalo nunca chega a `released`. A descida é imediata e barata: voltar
a estar vivo tem sempre de ser mais rápido do que parecer estar morto.

`dmks cancel --switch main --secret "$DMKS_OWNER_SECRET"` aborta a escalada a
partir de qualquer lado, com o secret do dono.

### Dois prazos em vez de três

Bastam dois prazos para o sistema funcionar. O estado `armed` existe como rede
de segurança, não comoobrigação: se não disseres nada, ele é calculado a meio.

```bash
python3 -m dmks init --warn-days 5 --release-days 20    # armed = dia 12
```

Com os dois prazos acima o sistema avisa-te no dia 5, insiste todos os dias a
partir do dia 12, e entrega no dia 20. O valor calculado fica gravado no
disco, para o motor nunca ter de adivinhar.

## Modos de entrega

- `hold` (omissão) — regista tudo, não envia nada. É o modo de ensaio.
- `notify` — email (SMTP) ou webhook com o pacote cifrado em anexo/base64.
- `publish` — copia o `.gpg` e um manifesto para `publish_dir`.

### Todos os canais recebem, não só o primeiro

Com SMTP e webhook configurados, o pacote sai por **ambos**. Se um falhar, o
outro continua a receber, a entrega só é marcada como feita quando todos
confirmam, e o canal que falhou é o único retomado na tentativa seguinte.

```bash
python3 -m dmks init \
  --smtp-host smtp.protonmail.ch --smtp-port 587 \
  --smtp-from eu@exemplo.pt --smtp-user eu@exemplo.pt \
  --webhook-url https://servico-a.example/hook \
  --webhook-url https://servico-b.example/hook \
  --release-mode notify
```

`--webhook-url` repete-se. Isto substituiu uma versão anterior que devolvia na
primeiratransporta que funcionasse — o que na prática significava a prova acabar
num sítio só, exactamente o que um switch não deve fazer.

### Email a partir do Proton Mail

O Proton não tem SMTP aberto. Só existem dois caminhos, e ambos exigem plano
pago:

| Caminho | Host | Credencial | Quando |
|---|---|---|---|
| SMTP Submission | `smtp.protonmail.ch:587` | SMTP token | plano pago **e domínio próprio** |
| Proton Mail Bridge | `127.0.0.1:1025` | Bridge password | plano pago, corre no teu máquina |

No plano gratuito não há saída por SMTP. O endereço `@proton.me` simplesmente
não pode ser remetido por um programa.

Com SMTP Submission, o token gera-se em Definições → Todas as definições →
IMAP/SMTP → SMTP tokens, e vai no `--smtp-password`:

```bash
python3 -m dmks init \
  --smtp-host smtp.protonmail.ch --smtp-port 587 \
  --smtp-from eu@meudominio.pt --smtp-user eu@meudominio.pt \
  --smtp-password "$TOKEN_SMTP" --release-mode notify
```

STARTTLS vem ligado, que é o que o Proton espera na 587.

**Sobre o Bridge:** ele corre no teu computador, o que significa que se o
computador estiver fechado quando o switch dispara, o pacote não sai. Para um
sistema que tem de funcionar sem ti, isso é um ponto único de falha. SMTP
Submission não tem o problema. Se ficares preso ao Bridge, coloca-o num
servidor teu em vez do portátil.

Se nenhum dos dois for possível, a alternativa honesta é um relay SMTP neutro
(Resend, Postmark, SES). Email é email; o que interessa é que exista mais do que
uma rota de saída.

## Limites, ditos com todas as letras

- **O tecto do relógio atrasa libertações, não as impede.** Com `max_credit` a
  3 dias e sem corroboração, um servidor que esteve 30 dias fora do ar precisa
  de ~10 avaliações para recuperar a escalada. Se isso for demasiado lento,
  configura `time_sources` para ter uma segunda fonte de tempo a confirmar.
- **Um check-in automático destrói o switch.** Se um `cron` faz check-in por ti,
  o aparelho nunca morre e a prova nunca sai. O check-in tem de exigir um humano,
  com nonce fresco.

- **Não é infallível.** Se morres e o pacote não chegou a lado nenhum, não há
  nada a fazer. É a razão de existirem as cópias redundantes.
- **Um atacante com o teu secret pode manter o switch quieto.** É o preço de
  não depender de bateria. Mitiga com quorum `all` e vários aparelhos.
- **Um canal de saída é um ponto único de falha.** Se só configurares um, e ele
  deixar de funcionar ou decidir engolir o pacote em silêncio, a prova está
  perdida mesmo que o sistema reporte sucesso. Configura pelo menos dois.
- **O formato OpenPGP tem data de validade.** As chaves que o GnuPG gera por
  omissão expiram. Para uma chave de longa vida, gera-a com
  `gpg --quick-generate-key "Advogado <adv@exemplo.pt>" default default never`
  e importá-la em qualquer lado que vá precisar de a abrir.
- **GitHub desactiva workflows agendados após 60 dias sem actividade.** Não
  deixes o cron redundante ser o *único* gatilho.
- **Publicar acusações automaticamente é risco legal.** Difamação, quebra de
  sigilo e responsabilidade civil não desaparecem por o conteúdo ser verdade.
  Entregar a um advogado é infinitamente mais seguro do que publicar. Fala com
  um advogado antes de escolher `publish`, e idealmente antes de selar.

## Legal

Isto não é aconselhamento jurídico. Publicar acusações não verificadas em nome
próprio tem consequências penais e civis reais, mesmo que as acusações sejam
verdadeiras e mesmo que tenhas provas. A ordem de utilização sensata:

1. Fala com um advogado. Pede a chave pública dele.
2. Entrega a ele (`notify`), não ao público (`publish`).
3. Se quiseres redundância pública, sela um pacote separado, só com o que o
   advogado tiver aprovado.
4. Regista-te como owner do destinatário, para receberes os avisos de `warn` e
   `armed`. São a tua última janela de cancelamento.

## Desenvolvimento

```bash
python3 -m dmks --data-dir data selftest   # auditoria + gpg + invariantes + testes
python3 -m unittest discover -s tests -t .
python3 scripts/demo_e2e.py                 # walkthrough completo, com gpg real
```

`scripts/demo_e2e.py` corre a CLI a sério contra uma chave GnuPG real e um
webhook local, faz o switch escalar de `warn` a `released`, e abre o pacote
entregue com a chave privada. Se isso completa, a cadeia inteira funciona.