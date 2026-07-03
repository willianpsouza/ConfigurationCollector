# ConfigurationCollector

Coletor de backup de configuração de switches/roteadores (Huawei VRP e afins) + auditoria determinística e aplicação de mudanças, escrito em Go.

Três binários, um só toolchain:

- **`collector`** — conecta via SSH/Telnet a partir de um `targets.json`, coleta config + estado (MPLS, interfaces, BGP/OSPF/ISIS) e persiste em disco.
- **`audit`** — lê as coletas e roda checagens determinísticas (rule engine) + camada opcional de LLM local (Ollama) para documentação/divergências.
- **`apply`** — aplica change-sets de configuração nos devices, com **dry-run por padrão**, backup do running antes, `commit` em roteador VRP8 e save opcional.

## Arquitetura

```
cmd/collector   entrypoint da coleta (one-shot; -only, -dry-run)
cmd/audit       auditoria + relatorios (md/json) + inventarios (csv)
cmd/apply       aplicacao de change-set (dry-run/-apply/-save)

internal/config     load/validate/resolve de targets.json
internal/vendor     driver plugavel por fabricante (huawei/zte/mikrotik/cisco)
internal/transport  SSH (shell+exec) e Telnet, robustos (pager, prompt, idle)
internal/collector  worker pool + retry + orquestracao
internal/storage    Store (interface) + Timestamped (arquivos datados)
internal/parse      parser dos arquivos coletados
internal/audit      rule engine deterministico + inventarios
internal/llm        cliente Ollama (documentacao/divergencias)
internal/apply      aplicacao de mudancas
```

Adicionar um vendor = implementar `vendor.Driver` e chamar `vendor.Register()` num `init()`; nenhum outro pacote muda.

## Uso

### Coleta

```bash
go build -o collector ./cmd/collector
./collector targets.json                 # coleta tudo
./collector -only 10.0.0.1 targets.json  # so um device
./collector -dry-run targets.json        # resolve alvos sem conectar
```

`targets.json` (ver `examples.json` / `multiples_examples.json`):

```json
{
  "base_dir": "./coletas",
  "timeout_seconds": 40,
  "concurrency": 5,
  "max_retries": 1,
  "ssh_legacy": { "enabled": true },
  "groups": [
    {
      "vendor": "huawei",
      "username": "admin",
      "password_env": "HUAWEI_PASS",
      "assets": [
        { "name": "CORE-01", "address": "10.0.0.1", "port": 22 },
        { "name": "SW-OLD",  "address": "10.0.0.2", "protocol": "telnet" }
      ]
    }
  ]
}
```

Credenciais: `password_env` (recomendado) ou `password`; override por asset. Saída: `base_dir/AAAA-MM-DD/NOME__IP__VENDOR__PROTO__HHMMSS.txt`.

### Auditoria

```bash
go build -o audit ./cmd/audit
./audit -input ./coletas                 # relatorio + inventarios
./audit -input ./coletas -focus          # so sinal acionavel (corta ruido)
./audit -input ./coletas -llm -model qwen2.5:14b   # + camada Ollama
```

Saídas: `audit-report.md`, `audit-findings.json`, `ip-inventory.csv`, `port-map.csv`.

Checagens determinísticas incluem: interface de cliente sem controle de banda/estatística, correlação de circuitos VLAN/L2VC/VSI ponta-A↔ponta-B, membership da malha MPLS, IP/rede duplicados, IP público em ativo interno, padronização de NTP/logging/timezone, portas ativas sem configuração e VLANs órfãs.

### Aplicação de mudanças

```bash
go build -o apply ./cmd/apply
./apply -targets targets.json -changeset changeset.json          # dry-run (padrao)
./apply -targets targets.json -changeset changeset.json -apply   # aplica no running
./apply -targets targets.json -changeset changeset.json -apply -save   # aplica + persiste
```

Segurança: dry-run é o padrão; `-apply` é explícito; backup do running-config é feito antes de cada device. Switch VRP5 = imediato; roteador VRP8 = aplicado após `commit`.

## Testes

```bash
go test ./... -cover
```
