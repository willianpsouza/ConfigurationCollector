# Instalação do LogBot (notifier)

Daemon que segue o `skynet.log`, classifica eventos de rede e alerta no Telegram.

## Config

```bash
mkdir -p ~/configcollector
cp deploy/logbot.conf.example ~/configcollector/logbot.conf
chmod 600 ~/configcollector/logbot.conf   # contém o token do bot
# editar: telegram_token, critical_chat, warning_chat (via /start no bot p/ pegar o chat_id)
```

Dica p/ os `chat_id`: rode o binário, mande `/start` no bot e ele responde com o id.

## Opção A — serviço de USUÁRIO (sem root/sudo) — usado no `provengo-access`

Requer que o bus de usuário exista (`systemctl --user` responde).

```bash
# binário cross-compilado p/ o servidor
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o notifier ./cmd/notifier   # copiar p/ ~/configcollector/

mkdir -p ~/.config/systemd/user
cp deploy/provengo-logbot.user.service ~/.config/systemd/user/provengo-logbot.service
export XDG_RUNTIME_DIR=/run/user/$(id -u)
systemctl --user daemon-reload
systemctl --user enable --now provengo-logbot
systemctl --user status provengo-logbot
journalctl --user -u provengo-logbot -f     # acompanhar
```

**Persistência no boot** (rodar sem sessão logada) precisa de linger — exige root uma vez:

```bash
# como root:
loginctl enable-linger willian_pires
```

## Opção B — serviço de SISTEMA (precisa root)

```bash
# como root:
mkdir -p /opt/provengo/logbot /etc/provengo/logbot
cp notifier /opt/provengo/logbot/
cp logbot.conf /etc/provengo/logbot/ && chmod 600 /etc/provengo/logbot/logbot.conf
cp deploy/provengo-logbot.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now provengo-logbot
systemctl status provengo-logbot
```

## Operação

```bash
systemctl --user restart provengo-logbot   # após trocar o binário/config
systemctl --user stop provengo-logbot
journalctl --user -u provengo-logbot -n 50  # logs
```
