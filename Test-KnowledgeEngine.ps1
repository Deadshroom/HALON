param(
    [switch]$ForceRebuild
)

$ErrorActionPreference = "Stop"

# ============================================================
# HALON KNOWLEDGE ENGINE REGRESSION
#
# Starts Python once.
# Loads BGE once.
# Rebuilds only missing/incomplete LanceDB family tables unless
# -ForceRebuild is explicitly requested.
# Writes full results to output\regression.
# ============================================================

$RepoRoot = "C:\Dev\halon"

$Python = Join-Path `
    $RepoRoot `
    ".venv\Scripts\python.exe"

$Runner = Join-Path `
    $RepoRoot `
    "src\knowledge\Test-KnowledgeEngine.py"


if (-not (Test-Path $Python)) {

    throw "HALON Python environment not found: $Python"
}


if (-not (Test-Path $Runner)) {

    throw "HALON regression runner not found: $Runner"
}


Set-Location $RepoRoot


$Arguments = @(
    $Runner
)


if ($ForceRebuild) {

    $Arguments += "--force-rebuild"
}


& $Python @Arguments


if ($LASTEXITCODE -ne 0) {

    throw "HALON regression runner failed with exit code $LASTEXITCODE"
}
