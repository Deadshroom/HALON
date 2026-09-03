$ErrorActionPreference = "Stop"

$RepoRoot = "C:\Dev\halon"

$Python = Join-Path `
    $RepoRoot `
    ".venv\Scripts\python.exe"

$Test = Join-Path `
    $RepoRoot `
    "src\reasoning\Test-ReasoningKnowledge.py"


if (-not (Test-Path $Python)) {

    throw (
        "HALON Python environment not found: " +
        $Python
    )
}


if (-not (Test-Path $Test)) {

    throw (
        "HALON Reasoning/Knowledge test not found: " +
        $Test
    )
}


Set-Location $RepoRoot


Write-Host ""
Write-Host "============================================================"
Write-Host " HALON Knowledge -> Reasoning Integration Test"
Write-Host "============================================================"
Write-Host ""


& $Python $Test


if ($LASTEXITCODE -ne 0) {

    throw (
        "HALON Knowledge -> Reasoning integration test failed " +
        "with exit code " +
        $LASTEXITCODE
    )
}
