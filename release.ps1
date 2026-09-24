<#
.SYNOPSIS
    Prepares a release: bumps the version everywhere it is written, commits, and tags.

.DESCRIPTION
    .\release.ps1 v0.2.4

    Run it on an up-to-date, clean main. It edits Cargo.toml, Cargo.lock, CHANGELOG.md (the
    Unreleased section becomes the new version), README.md and the bug report template, then
    makes a "Release vX.Y.Z" commit and an annotated tag. Nothing is pushed; the last line
    prints the push command, and the tag push is what starts the Release workflow.

    Cargo.lock is refreshed with the toolchain named by rust-version in Cargo.toml, because that
    is the strictest cargo CI runs: a newer cargo accepted a lock that 1.88 and the Docker build
    refused. It uses a local rustup toolchain of that version when one is installed, a local
    cargo of that version otherwise, and the rust:<version>-slim image through Docker when
    neither is present.
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Tag
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Exe $($Arguments -join ' ') exited with $LASTEXITCODE"
    }
}

function Read-Text([string]$Path) {
    [IO.File]::ReadAllText((Join-Path $root $Path))
}

# Writes UTF-8 without a BOM and leaves the line endings exactly as they were read.
function Write-Text([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText((Join-Path $root $Path), $Text, (New-Object Text.UTF8Encoding $false))
}

function Get-TomlValue([string]$Text, [string]$Key) {
    $m = [regex]::Match($Text, "(?m)^$Key\s*=\s*`"([^`"]+)`"")
    if (-not $m.Success) { throw "Cargo.toml has no $Key" }
    $m.Groups[1].Value
}

if ($Tag -notmatch '^v(\d+\.\d+\.\d+)$') {
    throw "expected a tag like v1.2.3, got '$Tag'"
}
$version = $Matches[1]
$root = $PSScriptRoot
$touched = @('Cargo.toml', 'Cargo.lock', 'CHANGELOG.md', 'README.md', '.github/ISSUE_TEMPLATE/bug_report.yml')

Push-Location $root
try {
    # --- Preconditions: nothing is edited until all of these pass ---

    $branch = (git rev-parse --abbrev-ref HEAD).Trim()
    if ($branch -ne 'main') { throw "releases are cut from main, not '$branch'" }
    if (git status --porcelain) { throw 'the working tree has uncommitted changes' }

    Invoke-Native git @('fetch', '--quiet', 'origin', 'main')
    $behind = [int](git rev-list --count HEAD..origin/main)
    if ($behind -gt 0) { throw "main is $behind commit(s) behind origin/main; pull first" }
    # The push that follows would carry any local commit into the release unreviewed.
    $ahead = [int](git rev-list --count origin/main..HEAD)
    if ($ahead -gt 0) { throw "main has $ahead commit(s) not on origin/main; release only what is merged" }

    git rev-parse --quiet --verify "refs/tags/$Tag" | Out-Null
    if ($LASTEXITCODE -eq 0) { throw "tag $Tag already exists locally" }
    if (git ls-remote --tags origin "refs/tags/$Tag") { throw "tag $Tag already exists on origin" }

    $cargoToml = Read-Text 'Cargo.toml'
    $current = Get-TomlValue $cargoToml 'version'
    $msrv = Get-TomlValue $cargoToml 'rust-version'
    if ([version]$version -le [version]$current) {
        throw "$version is not newer than the crate version $current"
    }

    $changelog = Read-Text 'CHANGELOG.md'
    $nl = if ($changelog.Contains("`r`n")) { "`r`n" } else { "`n" }
    $unreleased = [regex]::Match($changelog, '(?ms)^## \[Unreleased\][ \t]*\r?$(.*?)(?=^## \[)')
    if (-not $unreleased.Success) { throw 'CHANGELOG.md has no Unreleased section followed by a release' }
    if (-not $unreleased.Groups[1].Value.Trim()) { throw 'the Unreleased section of CHANGELOG.md is empty' }
    $firstLink = [regex]::Match($changelog, '(?m)^\[\d+\.\d+\.\d+\]: (\S+/releases/tag/)v')
    if (-not $firstLink.Success) { throw 'CHANGELOG.md has no release links to extend' }

    # --- Pick the cargo that refreshes Cargo.lock ---

    $cargo = $null
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        $pattern = '^' + [regex]::Escape($msrv) + '[.-]'
        $toolchain = $null
        if (Get-Command rustup -ErrorAction SilentlyContinue) {
            # rustup lists "1.88.0-x86_64-pc-windows-msvc"; "+1.88" would name a different toolchain.
            $toolchain = rustup toolchain list | Where-Object { $_ -match $pattern } |
                Select-Object -First 1 | ForEach-Object { ($_ -split '\s+')[0] }
        }
        if ($toolchain) {
            $cargo = @{ Exe = 'cargo'; Prefix = @("+$toolchain") }
        }
        elseif ((cargo --version) -match "^cargo $([regex]::Escape($msrv))\.") {
            $cargo = @{ Exe = 'cargo'; Prefix = @() }
        }
    }
    if (-not $cargo) {
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
            throw "no local cargo $msrv and no docker to run rust:$msrv-slim"
        }
        $cargo = @{
            Exe    = 'docker'
            Prefix = @('run', '--rm', '-v', "${root}:/src", '-v', 'sealref-cargo-registry:/usr/local/cargo/registry',
                '-w', '/src', "rust:$msrv-slim", 'cargo')
        }
    }
    Write-Host "cargo: $($cargo.Exe) $($cargo.Prefix -join ' ')"

    # --- Edits ---

    # Restored in finally rather than catch, so Ctrl+C during cargo also leaves a clean tree.
    $committed = $false
    try {
        $cargoToml = ([regex]'(?m)^version\s*=\s*"[^"]+"').Replace($cargoToml, "version = `"$version`"", 1)
        Write-Text 'Cargo.toml' $cargoToml

        $date = Get-Date -Format 'yyyy-MM-dd'
        $changelog = ([regex]'(?m)^## \[Unreleased\][ \t]*(?=\r?$)').Replace(
            $changelog, "## [Unreleased]$nl$nl## [$version] - $date", 1)
        $firstLink = [regex]::Match($changelog, '(?m)^\[\d+\.\d+\.\d+\]: (\S+/releases/tag/)v')
        $changelog = $changelog.Insert($firstLink.Index, "[$version]: $($firstLink.Groups[1].Value)$Tag$nl")
        Write-Text 'CHANGELOG.md' $changelog

        # Install commands, image tags and sample --version output name the release they describe.
        $mention = '(?<=sealref[ :]|sealref-v|releases/download/v)\d+\.\d+\.\d+'
        foreach ($doc in @('README.md', '.github/ISSUE_TEMPLATE/bug_report.yml')) {
            Write-Text $doc ([regex]::Replace((Read-Text $doc), $mention, $version))
        }

        Invoke-Native $cargo.Exe ($cargo.Prefix + @('update', '--workspace'))
        # Proves the lock now satisfies --locked, which is what CI and the release build pass.
        Invoke-Native $cargo.Exe ($cargo.Prefix + @('metadata', '--locked', '--format-version', '1')) | Out-Null

        # A release moves the crate version and nothing else in the lock; a dependency change
        # belongs in its own reviewed commit.
        $lockStat = (git diff --numstat -- Cargo.lock).Trim()
        if ($lockStat -notmatch '^1\s+1\s') {
            throw "Cargo.lock changed by more than the sealref version: '$lockStat'"
        }
        $unexpected = git diff --name-only | Where-Object { $touched -notcontains $_ }
        if ($unexpected) { throw "unexpected files changed: $($unexpected -join ', ')" }

        Invoke-Native git (@('add', '--') + $touched)
        Invoke-Native git @('commit', '--quiet', '-m', "Release $Tag")
        $committed = $true
    }
    finally {
        if (-not $committed) {
            Write-Host 'restoring the release files after the failure'
            git restore --staged --worktree -- @touched
        }
    }

    try {
        Invoke-Native git @('tag', '-a', $Tag, '-m', "sealref $version")
    }
    catch {
        throw "the release commit is made but tagging failed ($_). Tag it with: git tag -a $Tag -m `"sealref $version`""
    }

    Write-Host ''
    git show --stat --oneline HEAD
    Write-Host ''
    Write-Host "Tagged $Tag. Push the commit and the tag together to start the Release workflow:"
    Write-Host "  git push --atomic origin main $Tag"
}
finally {
    Pop-Location
}
