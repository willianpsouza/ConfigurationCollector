# 🆕 Novas Funcionalidades - Guia Completo

## 📋 Resumo das Novas Features

Esta versão adiciona **3 funcionalidades importantes**:

1. ✅ **Suporte a Telnet** - Para switches sem SSH
2. ✅ **Credenciais por Asset** - Override de user/pass por dispositivo
3. ✅ **Flag Active** - Desabilitar temporariamente assets sem remover do JSON

---

## 🔌 1. Suporte a Telnet

### Por que usar Telnet?

Alguns switches antigos não possuem SSH instalado ou habilitado. O Telnet permite coletar configurações desses dispositivos.

### Como configurar

#### Exemplo Básico

```json
{
  "groups": [
    {
      "vendor": "huawei",
      "username": "admin",
      "password_env": "HUAWEI_ADMIN_PASS",
      "assets": [
        {
          "name": "SWITCH-TELNET",
          "address": "10.0.0.1",
          "protocol": "telnet"
        }
      ]
    }
  ]
}
```

#### Portas

- **Porta padrão Telnet**: 23 (automático se não especificado)
- **Porta padrão SSH**: 22 (automático se não especificado)
- **Porta customizada**: Especifique explicitamente

```json
{
  "name": "SWITCH-CUSTOM",
  "address": "10.0.0.1",
  "port": 2323,
  "protocol": "telnet"
}
```

#### Protocolo Default

Se o campo `protocol` não for especificado, **SSH é usado por padrão**:

```json
{
  "name": "SWITCH-DEFAULT",
  "address": "10.0.0.1"
  // protocol não especificado = SSH (porta 22)
}
```

### ⚠️ Avisos de Segurança - Telnet

**Telnet é INSEGURO!**

- ❌ Tráfego em texto plano (senhas visíveis na rede)
- ❌ Sem criptografia
- ❌ Vulnerável a man-in-the-middle

**Use Telnet APENAS se:**
- ✅ Rede completamente isolada (VLAN de gerência)
- ✅ Sem acesso à internet
- ✅ Impossível habilitar SSH no switch
- ✅ Ambiente de lab/testes

**Recomendação:** Sempre que possível, habilite SSH no switch:
```bash
# Huawei - Habilitar SSH
stelnet server enable
ssh user admin authentication-type password
ssh user admin service-type stelnet

# ZTE - Habilitar SSH
ssh server enable
```

### Comparação SSH vs Telnet

| Feature | SSH | Telnet |
|---------|-----|--------|
| **Criptografia** | ✅ Sim | ❌ Não |
| **Segurança** | ✅ Alta | ❌ Nenhuma |
| **Porta padrão** | 22 | 23 |
| **Switches modernos** | ✅ Suportado | ⚠️ Depreciado |
| **Switches antigos** | ⚠️ Pode não ter | ✅ Geralmente tem |
| **Velocidade** | Rápido | Rápido |

---

## 🔑 2. Credenciais por Asset

### Por que usar?

Em alguns cenários, você precisa usar credenciais diferentes para dispositivos específicos:

- 🔐 Usuário de integração com permissões limitadas
- 🔐 Conta de API específica
- 🔐 Credenciais temporárias para coleta
- 🔐 Usuário read-only para compliance

### Como funciona

O coletor usa **hierarquia de credenciais**:

```
1. Credenciais do ASSET (se especificadas)
   ⬇️ (se não)
2. Credenciais do GRUPO
```

### Exemplos

#### Exemplo 1: Override de Username e Password

```json
{
  "groups": [
    {
      "vendor": "huawei",
      "username": "admin",
      "password_env": "HUAWEI_ADMIN_PASS",
      "assets": [
        {
          "name": "CORE01",
          "address": "10.0.0.1"
          // Usa: admin / HUAWEI_ADMIN_PASS (do grupo)
        },
        {
          "name": "CORE02-API",
          "address": "10.0.0.2",
          "username": "api_user",
          "password_env": "API_USER_PASS"
          // Usa: api_user / API_USER_PASS (do asset)
        }
      ]
    }
  ]
}
```

#### Exemplo 2: Diferentes Tipos de Credenciais

```json
{
  "groups": [
    {
      "vendor": "huawei",
      "username": "admin",
      "password_env": "ADMIN_PASS",
      "assets": [
        {
          "name": "SWITCH01-ADMIN",
          "address": "10.0.0.1"
          // Usa credenciais do grupo
        },
        {
          "name": "SWITCH02-INTEGRATION",
          "address": "10.0.0.2",
          "username": "integration",
          "password_env": "INTEGRATION_PASS"
          // Override completo
        },
        {
          "name": "SWITCH03-READONLY",
          "address": "10.0.0.3",
          "username": "readonly",
          "password": "senha_readonly_temporaria"
          // Override com senha em texto plano (não recomendado!)
        }
      ]
    }
  ]
}
```

#### Exemplo 3: Mix de Protocolos e Credenciais

```json
{
  "groups": [
    {
      "vendor": "zte",
      "username": "admin",
      "password_env": "ZTE_ADMIN_PASS",
      "assets": [
        {
          "name": "ZTE-SSH-ADMIN",
          "address": "10.1.0.1",
          "protocol": "ssh"
          // SSH com credenciais do grupo
        },
        {
          "name": "ZTE-TELNET-API",
          "address": "10.1.0.2",
          "protocol": "telnet",
          "username": "api_collector",
          "password_env": "API_PASS"
          // Telnet com credenciais específicas
        }
      ]
    }
  ]
}
```

### Variáveis de Ambiente

Configure todas as senhas necessárias:

```bash
# Credenciais do grupo
export HUAWEI_ADMIN_PASS='senha_admin'
export ZTE_ADMIN_PASS='senha_admin'

# Credenciais específicas de assets
export INTEGRATION_PASS='senha_integracao'
export API_USER_PASS='senha_api'
export READONLY_PASS='senha_readonly'
```

Ou no arquivo `.env`:
```bash
HUAWEI_ADMIN_PASS=senha_admin
INTEGRATION_PASS=senha_integracao
API_USER_PASS=senha_api
READONLY_PASS=senha_readonly
```

---

## ⏸️ 3. Flag Active (Ativo/Inativo)

### Por que usar?

A flag `active` permite **desabilitar temporariamente** um asset sem remover do JSON:

- 🔧 Switch em manutenção
- 🚧 Dispositivo ainda não instalado
- 🔄 Aguardando migração
- 🧪 Ambiente de testes
- 💤 Desligado temporariamente

### Como funciona

```json
{
  "name": "SWITCH01",
  "address": "10.0.0.1",
  "active": true   // ✅ Será coletado
}

{
  "name": "SWITCH02",
  "address": "10.0.0.2",
  "active": false  // ❌ NÃO será coletado
}

{
  "name": "SWITCH03",
  "address": "10.0.0.3"
  // active não especificado = true (default)
  // ✅ Será coletado
}
```

### Comportamento

| Valor de `active` | Comportamento |
|-------------------|---------------|
| `true` | ✅ Asset é coletado normalmente |
| `false` | ❌ Asset é IGNORADO (não tentará conectar) |
| Não especificado | ✅ Default = `true` (coletado) |

### Exemplos

#### Exemplo 1: Manutenção Programada

```json
{
  "groups": [
    {
      "vendor": "huawei",
      "username": "admin",
      "password_env": "HUAWEI_ADMIN_PASS",
      "assets": [
        {
          "name": "CORE01",
          "address": "10.0.0.1",
          "active": true,
          "_comment": "Produção normal"
        },
        {
          "name": "CORE02-MANUTENCAO",
          "address": "10.0.0.2",
          "active": false,
          "_comment": "Manutenção agendada 15-20/12 - Desabilitado temporariamente"
        }
      ]
    }
  ]
}
```

#### Exemplo 2: Planejamento de Expansão

```json
{
  "assets": [
    {
      "name": "ACC01",
      "address": "10.0.2.1",
      "active": true,
      "_comment": "Instalado e operacional"
    },
    {
      "name": "ACC02-PLANEJADO",
      "address": "10.0.2.2",
      "active": false,
      "_comment": "Instalação prevista para Jan/2025"
    },
    {
      "name": "ACC03-PLANEJADO",
      "address": "10.0.2.3",
      "active": false,
      "_comment": "Instalação prevista para Fev/2025"
    }
  ]
}
```

#### Exemplo 3: Ambientes Separados

```json
{
  "groups": [
    {
      "vendor": "huawei",
      "username": "admin",
      "password_env": "HUAWEI_ADMIN_PASS",
      "_comment": "Switches de Produção",
      "assets": [
        {
          "name": "PROD-CORE01",
          "address": "10.0.0.1",
          "active": true
        },
        {
          "name": "PROD-AGG01",
          "address": "10.0.1.1",
          "active": true
        }
      ]
    },
    {
      "vendor": "huawei",
      "username": "admin",
      "password_env": "HUAWEI_TEST_PASS",
      "_comment": "Switches de Teste - Desabilitados para coleta de produção",
      "assets": [
        {
          "name": "TEST-CORE01",
          "address": "10.99.0.1",
          "active": false
        },
        {
          "name": "TEST-AGG01",
          "address": "10.99.1.1",
          "active": false
        }
      ]
    }
  ]
}
```

### Logs

Quando um asset está inativo, o coletor registra nos logs:

```json
{
  "time": "2024-12-16T10:30:00Z",
  "level": "INFO",
  "msg": "asset inativo, ignorando",
  "asset": "CORE02-MANUTENCAO",
  "address": "10.0.0.2"
}
```

E no resumo final:

```json
{
  "time": "2024-12-16T10:30:05Z",
  "level": "INFO",
  "msg": "jobs enfileirados",
  "total_assets": 10,
  "active": 8,
  "inactive": 2
}
```

---

## 📊 Combinando Todas as Features

### Exemplo Completo Real

```json
{
  "base_dir": "./coletas",
  "timeout_seconds": 30,
  "concurrency": 5,
  "max_retries": 2,
  "ssh_legacy": {
    "enabled": true
  },
  "groups": [
    {
      "vendor": "huawei",
      "username": "admin",
      "password_env": "HUAWEI_ADMIN_PASS",
      "assets": [
        {
          "name": "CORE01-DC1",
          "address": "10.0.0.1",
          "protocol": "ssh",
          "active": true,
          "_comment": "Core principal - SSH moderno"
        },
        {
          "name": "CORE02-DC2",
          "address": "10.0.0.2",
          "protocol": "ssh",
          "active": true,
          "_comment": "Core secundário - SSH"
        },
        {
          "name": "AGG01-CAMPUS-OLD",
          "address": "10.0.1.1",
          "port": 23,
          "protocol": "telnet",
          "active": true,
          "_comment": "Switch antigo sem SSH - Telnet"
        },
        {
          "name": "AGG02-CAMPUS-API",
          "address": "10.0.1.2",
          "protocol": "ssh",
          "username": "integration",
          "password_env": "INTEGRATION_PASS",
          "active": true,
          "_comment": "Usa credencial de integração"
        },
        {
          "name": "AGG03-CAMPUS-MANUTENCAO",
          "address": "10.0.1.3",
          "protocol": "ssh",
          "active": false,
          "_comment": "Em manutenção até 20/12"
        },
        {
          "name": "ACC01-PREDIO-A",
          "address": "10.0.2.1",
          "protocol": "telnet",
          "port": 2323,
          "username": "readonly",
          "password_env": "READONLY_PASS",
          "active": true,
          "_comment": "Telnet porta custom + credencial específica"
        },
        {
          "name": "ACC02-PREDIO-B-FUTURO",
          "address": "10.0.2.2",
          "protocol": "ssh",
          "active": false,
          "_comment": "Planejado para instalação em Jan/2025"
        }
      ]
    }
  ]
}
```

Este exemplo mostra:
- ✅ SSH (CORE01, CORE02, AGG02, AGG03)
- ✅ Telnet (AGG01, ACC01)
- ✅ SSH Legacy habilitado
- ✅ Credenciais override (AGG02, ACC01)
- ✅ Porta customizada (ACC01)
- ✅ Assets inativos (AGG03, ACC02)
- ✅ Comentários documentando cada caso

---

## 🎯 Casos de Uso Práticos

### Caso 1: Migração SSH → Telnet

**Problema:** Switch teve SSH desabilitado temporariamente

**Solução:**
```json
{
  "name": "SWITCH01",
  "address": "10.0.0.1",
  "protocol": "telnet",  // ← Mudar de "ssh" para "telnet"
  "port": 23
}
```

### Caso 2: Múltiplas Credenciais

**Problema:** Alguns switches usam conta de integração, outros conta admin

**Solução:**
```json
{
  "groups": [
    {
      "username": "admin",
      "password_env": "ADMIN_PASS",
      "assets": [
        {
          "name": "SWITCH-ADMIN",
          "address": "10.0.0.1"
          // Usa admin
        },
        {
          "name": "SWITCH-API",
          "address": "10.0.0.2",
          "username": "integration",
          "password_env": "API_PASS"
          // Usa integration
        }
      ]
    }
  ]
}
```

### Caso 3: Coleta Seletiva

**Problema:** Quer testar com alguns switches antes de coletar todos

**Solução:**
```json
{
  "assets": [
    {
      "name": "CORE01-TESTE",
      "address": "10.0.0.1",
      "active": true   // ← Habilitar apenas este
    },
    {
      "name": "AGG01",
      "address": "10.0.1.1",
      "active": false  // ← Desabilitar temporariamente
    },
    {
      "name": "AGG02",
      "address": "10.0.1.2",
      "active": false  // ← Desabilitar temporariamente
    }
  ]
}
```

### Caso 4: Ambiente Misto Legacy

**Problema:** Mix de switches antigos (Telnet) e novos (SSH moderno)

**Solução:**
```json
{
  "ssh_legacy": {
    "enabled": true  // Habilita algoritmos antigos para SSH
  },
  "groups": [
    {
      "assets": [
        {
          "name": "OLD-TELNET",
          "protocol": "telnet"  // Muito antigo, só Telnet
        },
        {
          "name": "OLD-SSH",
          "protocol": "ssh"  // Antigo, SSH com algoritmos legacy
        },
        {
          "name": "NEW-SSH",
          "protocol": "ssh"  // Moderno, funciona com ou sem legacy
        }
      ]
    }
  ]
}
```

---

## 📝 Formato dos Arquivos de Saída

Os arquivos incluem agora o protocolo no nome:

```
NOME__IP__VENDOR__PROTOCOL__TIMESTAMP.txt
```

**Exemplos:**
```
CORE01__10.0.0.1__huawei__ssh__143022.txt
AGG01-OLD__10.0.1.1__huawei__telnet__143045.txt
ZTE-CORE__10.1.0.1__zte__ssh__143112.txt
```

---

## ⚙️ Instalação e Dependências

### Dependência Telnet

O código usa a biblioteca `github.com/ziutek/telnet`:

```bash
go get github.com/ziutek/telnet
```

### Compilação

```bash
# Instalar todas as dependências
go get golang.org/x/crypto/ssh
go get github.com/ziutek/telnet

# Compilar
go build -o collector collector-final.go
```

---

## 🔍 Validação

O coletor valida:

✅ Protocolo (deve ser "ssh" ou "telnet")  
✅ Portas (0-65535)  
✅ Credenciais (grupo ou asset deve ter senha)  
✅ Vendor (deve ser "huawei" ou "zte")  

Erros são reportados antes da execução:

```json
{
  "level": "ERROR",
  "msg": "config inválida",
  "error": "grupo[0].assets[2]: protocolo inválido \"ftp\" (use ssh ou telnet)"
}
```

---

## 🎓 Resumo Final

| Feature | Campo JSON | Default | Exemplo |
|---------|-----------|---------|---------|
| **Protocolo** | `protocol` | `"ssh"` | `"telnet"` |
| **Username por Asset** | `username` | Do grupo | `"integration"` |
| **Password por Asset** | `password` ou `password_env` | Do grupo | `"API_PASS"` |
| **Ativo/Inativo** | `active` | `true` | `false` |
| **Porta** | `port` | 22 (SSH) ou 23 (Telnet) | `2323` |

---

## 📚 Arquivos de Exemplo

- **targets-complete.json** - Exemplo completo com todas features
- **targets-telnet.json** - Foco em Telnet
- **targets-custom-credentials.json** - Foco em credenciais por asset
- **targets-active-inactive.json** - Foco em flag active

---

**Todas as funcionalidades estão prontas! 🚀**
