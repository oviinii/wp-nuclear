# wp-nuclear 🛡️

Auditoria e limpeza guiada de WordPress comprometido, via FTP — 100% Python 3.9+ stdlib (zero dependências).

Criado a partir do playbook real usado na limpeza dos sites comprometidos com os kits **KGS** e **NOX-CLOAK** (outubro/2026).

## ⚡ Instalação

```bash
# Requisito: Python 3.9+
# Arquivos:
#   wp_nuclear.py    – a ferramenta (CLI)
#   wpn_web.py       – interface web local (dashboard)
#   signatures.json  – assinaturas extensíveis
```

## 📖 Uso

### 1. SCAN (audit-only, não altera nada)

```bash
python3 wp_nuclear.py scan \
  --host ftp.seudominio.com.br \
  --user u999999999.seudominio.com.br \
  --domain https://seudominio.com.br \
  --db-probe \
  --json report.json --html report.html
```

- Auto-detecta a raiz do WP (`/public_html` ou o CWD do FTP)
- Se `--db-probe`: sobe um probe PHP temporário (removido automaticamente) para auditar o banco:
  usuários, admin fantasma, Application Passwords, opções-chave
- Gera relatório JSON + HTML com gravidades: `high` (maliciosa confirmada), `warn`, `review`

### 2. CLEAN (aplica a limpeza, com confirmação interativa)

```bash
# passo a passo (revisar sem executar)
python3 wp_nuclear.py clean --report report.json

# executar de verdade (pede senha FTP + digitação de "LIMPAR")
python3 wp_nuclear.py clean --report report.json --host HOST --user USER --execute
```

O que o clean faz:
- Move os artefatos high para `/quarantine_wpn_<timestamp>/` (fora do docroot)
- Renomeia `index_original.php` → `index.php` (restaura frontpage)
- Reescreve `.htaccess` removendo blocos do KGS_BOT_RULE/NOX-CLOAK-RULE
- Reescreve `robots.txt` se contiver sitemap do kit (`sitemap36.xml` etc.)
- Faz **backup local** de cada arquivo movido (em `./wpn_backups/`)

### 3. SALTS (rotaciona chaves/salts do wp-config)

```bash
python3 wp_nuclear.py salts --report report.json --host HOST --user USER --execute
# pede digitação de "SALTS" para confirmar; backup local antes
```

### 4. DB (auditoria/limpeza de banco via probe)

```bash
# auditoria
python3 wp_nuclear.py db --report report.json --host HOST --user USER
# limpar ghosts (crt_*, admin_*) e resetar senhas de admins
python3 wp_nuclear.py db --report report.json --host HOST --user USER --execute --resetpass --domain https://Site
```

### 5. MONITOR (baseline vs agora)

```bash
python3 wp_nuclear.py monitor --report report_hoje.json --baseline report_ontem.json
```

## 🔎 O que o scanner detecta

**Assinatura do kit KGS** (incidente 2026-10): `mrkt.php`, `ex.php`, `wp-card.php`,
`admin-clor.php`, `cache-cleaner.php`, `amp.php`, bloco `KGS_BOT_RULE` em `.htaccess`,
`sitemap36.xml`, chaves IndexNow falsas, `index_original.php` (index.php renaming)
  
**Assinatura do kit NOX-CLOAK** (incidente 2026-09): `mu-plugins/nox-engine.php`,
`.wp-config/` (stash com `perde.html` shell UI, cloak.lock, audit.log do atacante),
`.user.ini` com `auto_prepend_file`, `.nox_*.meta`, bloco `NOX-CLOAK-RULE`

**Genérico:** `eval(base64_decode...)`, webshells (`filesman`,`c99`,`r57`), PHPs em
`wp-content/uploads`, `mostrar Wp Auto-update-core=false`, mu-plugins fora da whitelist
(hostinger-*), plugins-fantasma (dir só com `functions_bak.php`), dir com nome
aleatório, `.htaccess` com cloaking de bots, WP salts vazias.

## ⚠️ Precauções

- A senha **não é gravada em relatório** — escrevemos do stdin/env a cada execução.
- No modo `clean --execute`, todos os arquivos movidos têm **copy local** em `./wpn_backups/`.
- O "probe" PHP (`db`, `--db-probe`) é criado, roda e é removido na sequência.
- **Não é invasivo**: NEM edita o WP core, NEM toca em conteúdo; só oneração a quarentena.

## 🖥️ Interface web (dashboard local)

Painel no estilo Apple HIG (macOS): sidebar translúcida, light/dark automático, alerts com confirmação digitada. Senhas ficam apenas em memória.

```bash
python3 wpn_web.py            # abre em http://localhost:8787
```

Fluxo: formulario de conexão → **Escanear Site** → log ao vivo → relatório com achados → **Limpar Achados** (plano + digitação de `LIMPAR`) → rescan confirma `high=0`. Ações rápidas na sidebar: rotacionar salts, probe do banco.

## 🚧 Roadmap v2  (to-do)
- SFTP (porta 65002 Hostinger) via opção — hoje: porta 21
- comparação contra assinatura MD5 oficial via api.wordpress.org (WP core diff real)
- baseline + monitor agendado (cron)
- exportação em PDF
- suporte a múltiplos sites fixados no painel

## 📄 Estrutura do código

```
wp_nuclear.py     CLI (scan / clean / salts / db / monitor)
wpn_web.py        interface web local (stdlib http.server, zero deps)
signatures.json   assinaturas (extensível sem tocar no código)
reports/          saída dos scans      (fora do git)
wpn_backups/      backups pre-limpeza  (fora do git)
```

---
⚠️ Aviso: essa ferramenta opera exclusivamente em infraestrutura que você tem autorização
administrativa para auditar/limpar. Uso não autorizado é ilegal.

---

## 🧪 Laboratório local (site WP "infectado" para testes)

Réplica local com o kit KGS + NOX-CLOAK reais, exposta via FTP local:

```bash
# 1. subir FTP do lab        (porta 2121, só localhost)
python3 ~/wpn-lab/ftp_server.py

# 2. subir a interface
python3 ~/Desktop/wp-nuclear/wpn_web.py

# 3. abrir http://localhost:8787 e conectar no lab:
#    Host: 127.0.0.1   Usuário: wpnlab   Senha: lab12345   Porta: 2121
```

Credenciais do lab: `wpnlab / lab12345` · chroot: `~/wpn-lab` (o scanner acha `/public_html` sozinho).
Arquivos maliciosos reais em `~/wpn-lab/public_html/`; limpeza os move para `quarantine_wpn_*` dentro do lab.
