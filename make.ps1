<#
.SYNOPSIS
  Windows task runner. Mirrors the Makefile targets one-for-one.

.DESCRIPTION
  GNU make is not present on a default Windows install, and the project has to
  be developable there — the artifacts Sightglass analyses are mostly Windows
  binaries, so a Windows dev box is a first-class environment, not an
  afterthought.

  Every target here must match the Makefile target of the same name. If you add
  one there, add it here.

.EXAMPLE
  ./make.ps1 test
  ./make.ps1 sandbox-check
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target = 'help',

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$RunRoot = if ($env:SIGHTGLASS_RUN_ROOT) { $env:SIGHTGLASS_RUN_ROOT }
           else { Join-Path $PSScriptRoot 'var\runs' }

$ComposeDev = @('compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml')

function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    Write-Host "> $Exe $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe exited with $LASTEXITCODE" }
}

function Invoke-Uv { param([string[]]$Arguments) Invoke-Checked 'uv' (@('run') + $Arguments) }
function Invoke-Docker { param([string[]]$Arguments) Invoke-Checked 'docker' $Arguments }

function Initialize-RunRoot {
    if (-not (Test-Path $RunRoot)) { New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null }
    $env:SIGHTGLASS_RUN_ROOT = $RunRoot
    Write-Host "run root: $RunRoot" -ForegroundColor DarkGray
}

$Targets = [ordered]@{
    'install'          = { Invoke-Checked 'uv' @('sync', '--extra', 'dev') }
    'run-root'         = { Initialize-RunRoot }

    'dev'              = { Initialize-RunRoot; Invoke-Docker ($ComposeDev + @('up', '--build')) }
    'dev-detached'     = { Initialize-RunRoot; Invoke-Docker ($ComposeDev + @('up', '--build', '-d')) }
    'down'             = { Invoke-Docker ($ComposeDev + @('down', '--remove-orphans')) }
    'clean'            = { Invoke-Docker ($ComposeDev + @('down', '--remove-orphans', '--volumes')) }
    'logs'             = { Invoke-Docker ($ComposeDev + @('logs', '-f')) }

    'images'           = { Invoke-Docker @('build', '-t', 'sightglass/hello:dev', 'sandbox/images/hello') }
    'image-hello'      = { Invoke-Docker @('build', '-t', 'sightglass/hello:dev', 'sandbox/images/hello') }
    'refresh-digests'  = {
        foreach ($image in @('python:3.12-slim-bookworm')) {
            Invoke-Docker @('pull', '-q', $image)
            $digest = & docker inspect --format '{{index .RepoDigests 0}}' $image
            '{0,-32} {1}' -f $image, $digest
        }
    }

    'test'             = { Invoke-Uv @('pytest', 'tests/unit', '-v') }
    'test-integration' = { Invoke-Uv @('pytest', 'tests/integration', '-v', '-m', 'integration') }
    'test-all'         = { Invoke-Uv @('pytest', '-v') }
    'lint'             = { Invoke-Uv @('ruff', 'check', '.'); Invoke-Uv @('ruff', 'format', '--check', '.') }
    'format'           = { Invoke-Uv @('ruff', 'format', '.'); Invoke-Uv @('ruff', 'check', '--fix', '.') }
    'typecheck'        = { Invoke-Uv @('mypy') }
    'secrets'          = {
        Invoke-Docker @('run', '--rm', '-v', "${PSScriptRoot}:/repo",
                        'zricethezav/gitleaks:latest', 'detect', '--source', '/repo', '--redact')
    }
    'check'            = { & $PSCommandPath 'lint'; & $PSCommandPath 'typecheck'; & $PSCommandPath 'test' }

    'sandbox-check'    = {
        & $PSCommandPath 'image-hello'
        Initialize-RunRoot
        Invoke-Uv @('sightglass', 'sandbox', 'health')
        Invoke-Uv @('sightglass', 'sandbox', 'hello')
    }

    'corpus'           = { throw 'make corpus is not implemented yet; scheduled for M2 (see CLAUDE.md)' }
    'airgap-bundle'    = { throw 'make airgap-bundle is not implemented yet; scheduled for M6 (see CLAUDE.md)' }
}

if ($Target -in @('help', '--help', '-h', '--list')) {
    Write-Host 'Sightglass targets:' -ForegroundColor Cyan
    $Targets.Keys | ForEach-Object { "  $_" }
    exit 0
}

if (-not $Targets.Contains($Target)) {
    Write-Error "unknown target '$Target'. Run ./make.ps1 help for the list."
    exit 1
}

& $Targets[$Target]
