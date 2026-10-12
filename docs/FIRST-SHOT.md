# FIRST-SHOT.md — como configurar e disparar o primeiro e-mail (passo a passo)

Guia prático. Substitui os valores `<...>` pelos teus. Tudo a partir da raiz do projeto.

---

## 0. Pré-requisitos
- Python 3.11+ e **GnuPG** (`gpg`).
- Uma caixa **Zoho** (`gsantos@binaryxz.com`) e um **app-password** dela
  (Zoho → Settings → Security → App Passwords).

```bash
cd /home/user/dead_man_kill_switch
export PYTHONPATH=.
```

---

## 1. Chave GPG de quem RECEBE (o destinatário)
O pacote é cifrado para o destinatário; o servidor só precisa da **chave pública**.

Na máquina do destinatário (ou onde tens a chave privada):
```bash
gpg --full-generate-key                 # ou usa uma chave existente
gpg --armor --export destinatario@exemplo.pt > destinatario.asc
```

No servidor, importa a chave pública e copia o fingerprint:
```bash
gpg --import destinatario.asc
gpg --list-keys --with-colons | grep '^fpr' | head -1
```
Guarda esse fingerprint — precisas no passo 5.

---

## 2. A password de envio vai para o ambiente, nunca para o ficheiro
```bash
export SMTP_PASSWORD="o-teu-app-password-do-zoho"
```
No config fica só o marcador `env:SMTP_PASSWORD`.

---

## 3. Criar o switch (data-dir fixo, fora de /tmp)
```bash
export DMC="$HOME/dmks-live"

python3 -m dmks --data-dir "$DMC" init \
  --switch principal --name "prova de vida" \
  --release-mode notify \
  --smtp-host smtp.zoho.com --smtp-port 587 \
  --smtp-from gsantos@binaryxz.com \
  --smtp-user gsantos@binaryxz.com \
  --smtp-password 'env:SMTP_PASSWORD' \
  --owner-email gsantos@binaryxz.com \
  --warn-days 15 --arm-days 20 --release-days 25 \
  --tick-seconds 3600
```
Guarda o `tick token` que ele imprime (serve para o cron, passo 8).

---

## 4. Enrolar os dispositivos (telemóvel / portátil)
```bash
python3 -m dmks --data-dir "$DMC" enroll --device phone  --label telemovel
python3 -m dmks --data-dir "$DMC" enroll --device laptop --label portatil
```
Cada comando imprime um `secret`. **Esse secret vive no dispositivo**, não no servidor.
É com ele que fazes o check-in (passo 7).

---

## 5. Registar o destinatário (com a chave GPG do passo 1)
```bash
python3 -m dmks --data-dir "$DMC" recipient add \
  --address destinatario@exemplo.pt \
  --gpg <FINGERPRINT_DO_PASSO_1>
```

---

## 6. Selar a evidência (isto vira o ANEXO do e-mail)
```bash
python3 -m dmks --data-dir "$DMC" seal --note "dossier" /caminho/para/evidencia.pdf
```
Produz um pacote `.gpg` em `$DMC/packets/`. O servidor **nunca** vê o conteúdo em claro.

---

## 7. Check-in (prova de vida) — o dia a dia
De cada dispositivo, sempre que estiveres vivo:
```bash
python3 -m dmks --data-dir "$DMC" checkin --device phone --secret <secret_do_phone>
python3 -m dmks --data-dir "$DMC" checkin --device laptop --secret <secret_do_laptop>
```
Sem check-ins, o silêncio é contado desde a criação do switch.

---

## 8. Pôr a vigiar (produção)
Loop principal:
```bash
python3 -m dmks --data-dir "$DMC" worker
```
E, em paralelo, um **tick externo** (cron) — garante que dispara mesmo se o worker morrer:
```bash
# a cada hora; troca o token pelo do passo 3
curl -s -X POST -H "Authorization: Bearer <TICK_TOKEN>" http://127.0.0.1:8770/api/tick
```

Painel web (opcional):
```bash
python3 -m dmks --data-dir "$DMC" owner-password    # define a password do painel
python3 -m dmks --data-dir "$DMC" serve
```

---

## 9. O disparo
Se o dono ficar em silêncio: **warn (15d) → armed (20d) → released (25d)**.
No `released`, o switch envia o e-mail para o destinatário **com o anexo `.gpg`**.

---

## 10. Testar JÁ, sem esperar 25 dias
Simula o futuro com `tick --now` (epoch em segundos):
```bash
python3 -m dmks --data-dir "$DMC" tick --now $(($(date +%s) + 26*86400))
```
Isso avalia como se já tivessem passado 26 dias de silêncio e dispara a entrega.

> Há um script pronto que faz a cadeia toda local e confirma o anexo:
> `python3 scripts/demo_first_shot.py`
