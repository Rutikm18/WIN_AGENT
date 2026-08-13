Windows Security Audit

Current verified Windows implementation is in [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md). This document is retained as additional design context. Startup diagnostics and safe automated recovery are documented in [`advanced_support/`](advanced_support/README.md).

Run the following commands in PowerShell, preferably as Administrator where required.

1. VS Code and Cursor extensions
code --list-extensions --show-versions
cursor --list-extensions --show-versions

Filter likely AI and security-sensitive extensions:

@(
    code --list-extensions --show-versions 2>$null
    cursor --list-extensions --show-versions 2>$null
) | Select-String -Pattern `
"copilot|cline|roo|continue|claude|gemini|codex|openai|codeium|windsurf|tabnine|mcp|remote|ssh|docker|kubernetes|rest|database"

Extension directories:

Get-ChildItem "$env:USERPROFILE\.vscode\extensions"
Get-ChildItem "$env:USERPROFILE\.cursor\extensions"

Search extension manifests:

Get-ChildItem `
"$env:USERPROFILE\.vscode\extensions",
"$env:USERPROFILE\.cursor\extensions" `
-Recurse -Filter package.json -ErrorAction SilentlyContinue |
Select-String -Pattern `
'"activationEvents"|"onStartupFinished"|"workspaceContains"|"child_process"|"shell"|"terminal"|"http"|"https"'
2. MCP server configurations

Claude Desktop configuration:

$ClaudeConfig = "$env:APPDATA\Claude\claude_desktop_config.json"
Get-Content $ClaudeConfig

Pretty-print it:

Get-Content $ClaudeConfig -Raw |
ConvertFrom-Json |
ConvertTo-Json -Depth 20

List configured MCP servers:

$config = Get-Content $ClaudeConfig -Raw | ConvertFrom-Json

$config.mcpServers.PSObject.Properties | ForEach-Object {
    [PSCustomObject]@{
        Name    = $_.Name
        Command = $_.Value.command
        Args    = $_.Value.args -join " "
    }
}

Search for MCP files:

$locations = @(
    "$env:APPDATA\Claude",
    "$env:APPDATA\Cursor",
    "$env:APPDATA\Code",
    "$env:USERPROFILE\.cursor",
    "$env:USERPROFILE\.vscode",
    "$env:USERPROFILE\.config"
)

Get-ChildItem $locations -Recurse -File -ErrorAction SilentlyContinue |
Where-Object {
    $_.Name -match "mcp|config" -and
    $_.Extension -match "\.(json|jsonc|yaml|yml)$"
} |
Select-Object FullName

Search configuration contents:

Get-ChildItem $locations -Recurse -File -ErrorAction SilentlyContinue |
Where-Object Extension -Match "\.(json|jsonc|yaml|yml)$" |
Select-String -Pattern `
'"mcpServers"|mcp-server|mcp_server|model.context.protocol' |
Select-Object Path, LineNumber, Line
3. Global Node.js packages
npm list -g --depth=0
npm root -g
npm config get prefix

Filter likely AI packages:

npm list -g --depth=0 |
Select-String -Pattern `
"mcp|modelcontext|claude|openai|gemini|copilot|agent|langchain|crewai|autogen|ollama|llama"

Other package managers:

pnpm list -g --depth=0
yarn global list
bun pm ls -g

Inspect npm configuration:

npm config list
npm config get registry
npm config get proxy
npm config get https-proxy
npm config get ignore-scripts

Find .npmrc files:

Get-ChildItem $env:USERPROFILE -Recurse -Filter ".npmrc" `
-ErrorAction SilentlyContinue
4. Python packages

List installed Python versions:

py -0p

Inspect the default Python environment:

python -m pip list
python -m pip freeze
python -m pip list --editable

Filter AI and agent packages:

python -m pip list |
Select-String -Pattern `
"mcp|openai|anthropic|langchain|langgraph|crewai|autogen|transformers|ollama|llama|agent"

Inspect pip configuration:

python -m pip config list
python -m pip config debug

Generate package inventory:

python -m pip inspect > pip-inventory.json
5. Installed applications
Winget
winget list

Filter AI and developer applications:

winget list |
Select-String -Pattern `
"Claude|Cursor|Windsurf|ChatGPT|Ollama|LM Studio|Visual Studio Code|Python|Node"
Chocolatey
choco list
Scoop
scoop list
Registry-based application inventory
$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

Get-ItemProperty $registryPaths -ErrorAction SilentlyContinue |
Where-Object DisplayName |
Sort-Object DisplayName |
Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation

Filter likely AI tools:

Get-ItemProperty $registryPaths -ErrorAction SilentlyContinue |
Where-Object {
    $_.DisplayName -match `
    "Claude|Cursor|Windsurf|ChatGPT|Ollama|LM Studio|Copilot|Visual Studio Code"
} |
Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation
6. AI and agent CLI tools
$commands = @(
    "claude",
    "codex",
    "gemini",
    "aider",
    "ollama",
    "cursor",
    "code",
    "continue",
    "cline",
    "goose",
    "opencode",
    "fabric",
    "sgpt",
    "uv",
    "uvx",
    "npx",
    "docker"
)

foreach ($command in $commands) {
    $result = Get-Command $command -ErrorAction SilentlyContinue

    if ($result) {
        [PSCustomObject]@{
            Command = $command
            Path    = $result.Source
            Type    = $result.CommandType
        }
    }
}

Find duplicate or shadowed commands:

Get-Command python -All
Get-Command node -All
Get-Command npm -All
Get-Command code -All
7. PowerShell profiles

Show profile paths:

$PROFILE | Format-List *

Read all existing profiles:

$profiles = @(
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost
)

$profiles |
Where-Object { Test-Path $_ } |
ForEach-Object {
    Write-Host "`n===== $_ ====="
    Get-Content $_
}

Search for suspicious startup commands:

$profiles |
Where-Object { Test-Path $_ } |
ForEach-Object {
    Select-String -Path $_ -Pattern `
    "Invoke-WebRequest|curl|wget|iex|Invoke-Expression|npm|npx|python|pip|uvx|mcp|agent|ollama|claude|cursor"
}

Inspect PATH:

$env:PATH -split ";"
8. Scheduled tasks
Get-ScheduledTask |
Where-Object State -ne "Disabled" |
Select-Object TaskPath, TaskName, State

Show executable commands:

Get-ScheduledTask | ForEach-Object {
    foreach ($action in $_.Actions) {
        [PSCustomObject]@{
            Task       = "$($_.TaskPath)$($_.TaskName)"
            Execute    = $action.Execute
            Arguments  = $action.Arguments
            WorkingDir = $action.WorkingDirectory
        }
    }
}

Filter suspicious tasks:

Get-ScheduledTask | ForEach-Object {
    foreach ($action in $_.Actions) {
        if (
            $action.Execute -match `
            "powershell|cmd|python|node|npm|npx|uvx|curl|wscript|cscript"
        ) {
            [PSCustomObject]@{
                Task      = "$($_.TaskPath)$($_.TaskName)"
                Execute   = $action.Execute
                Arguments = $action.Arguments
            }
        }
    }
}
9. Windows services
Get-CimInstance Win32_Service |
Select-Object Name, State, StartMode, PathName |
Sort-Object Name

Filter relevant services:

Get-CimInstance Win32_Service |
Where-Object {
    $_.PathName -match `
    "python|node|npm|npx|ollama|claude|cursor|agent|mcp"
} |
Select-Object Name, State, StartMode, PathName

Pay attention to:

Unquoted service paths
Services running from user profile folders
Services launching PowerShell or command files
Unknown auto-start services
10. Startup entries
Get-CimInstance Win32_StartupCommand |
Select-Object Name, Command, Location, User

Check Run registry keys:

$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "`n===== $key ====="
        Get-ItemProperty $key
    }
}
11. Running processes
Get-Process |
Where-Object ProcessName -Match `
"mcp|claude|ollama|openai|gemini|aider|cursor|code|python|node" |
Select-Object Id, ProcessName, Path

Show command-line arguments:

Get-CimInstance Win32_Process |
Where-Object CommandLine -Match `
"mcp|claude|ollama|openai|gemini|cline|continue|cursor|agent" |
Select-Object ProcessId, ParentProcessId, Name, CommandLine
12. Listening ports
Get-NetTCPConnection -State Listen |
Select-Object LocalAddress, LocalPort, OwningProcess

Resolve process names:

Get-NetTCPConnection -State Listen | ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        Address = $_.LocalAddress
        Port    = $_.LocalPort
        PID     = $_.OwningProcess
        Process = $process.ProcessName
        Path    = $process.Path
    }
}

Pay special attention to listeners on:

0.0.0.0
::
13. Browser extensions
Chrome
Get-ChildItem `
"$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" `
-ErrorAction SilentlyContinue
Microsoft Edge
Get-ChildItem `
"$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" `
-ErrorAction SilentlyContinue

Search extension manifests:

$browserLocations = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
)

Get-ChildItem $browserLocations -Recurse -Filter manifest.json `
-ErrorAction SilentlyContinue |
Select-String -Pattern `
'"permissions"|"host_permissions"|"nativeMessaging"|"clipboardRead"|"cookies"|"history"|"debugger"|"webRequest"'
14. Browser Native Messaging hosts
$nativeKeys = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts",
    "HKLM:\Software\Google\Chrome\NativeMessagingHosts",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts",
    "HKLM:\Software\Microsoft\Edge\NativeMessagingHosts"
)

foreach ($key in $nativeKeys) {
    if (Test-Path $key) {
        Write-Host "`n===== $key ====="
        Get-ChildItem $key
    }
}

Read the configured host manifest location:

Get-ItemProperty `
"HKCU:\Software\Google\Chrome\NativeMessagingHosts\*" `
-ErrorAction SilentlyContinue
15. Git configuration and hooks
git config --global --show-origin --list
git config --system --show-origin --list
git config --local --show-origin --list

Check sensitive configuration:

git config --show-origin --get core.hooksPath
git config --show-origin --get credential.helper
git config --show-origin --get core.sshCommand

Inspect repository hooks:

Get-ChildItem .git\hooks -File -ErrorAction SilentlyContinue

Review repository execution files:

.vscode\tasks.json
.vscode\settings.json
.vscode\launch.json
.devcontainer\devcontainer.json
Dockerfile
docker-compose.yml
Makefile
package.json
pyproject.toml
requirements.txt
.github\workflows\
16. Credential and secret locations

List saved Windows credentials:

cmdkey /list

Inspect common credential folders:

Get-ChildItem `
"$env:USERPROFILE\.aws",
"$env:USERPROFILE\.azure",
"$env:USERPROFILE\.docker",
"$env:USERPROFILE\.kube",
"$env:USERPROFILE\.ssh" `
-Force -Recurse -ErrorAction SilentlyContinue

Find likely secret files without printing contents:

Get-ChildItem $env:USERPROFILE -Recurse -File `
-ErrorAction SilentlyContinue |
Where-Object {
    $_.Name -match `
    "^\.env$|credential|secret|token|config"
} |
Select-Object FullName
17. Docker
docker ps -a
docker images --digests
docker volume ls
docker network ls

Filter AI-related containers:

docker ps -a --format "{{.Names}}`t{{.Image}}" |
Select-String -Pattern `
"mcp|ollama|open-webui|langchain|agent|claude|openai|llama"

Inspect each container:

docker inspect CONTAINER_NAME

Look for:

Privileged: true
Docker socket mounts
Host root filesystem mounts
Host networking
SYS_ADMIN
Plaintext secrets in environment variables
Images using latest
Unknown registries
Highest-priority checks

For both operating systems, investigate in this order:

MCP server commands and permissions
VS Code, Cursor and browser extensions
Startup persistence and scheduled execution
Global npm and Python packages
Listening services and network exposure
Git hooks and workspace task files
Plaintext secrets and credential directories
Docker socket, privileged containers and host mounts
Unknown package registries and unpinned dependencies
Old or unused tools with excessive permissions
