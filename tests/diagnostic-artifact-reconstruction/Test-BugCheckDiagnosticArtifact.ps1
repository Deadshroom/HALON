$ErrorActionPreference = "Stop"


# ============================================================
# HALON
# Diagnostic Artifact Reconstruction Capability Test
#
# Purpose:
# Prove that HALON can deterministically identify a diagnostic
# artifact produced by a Windows BugCheck incident using
# evidence already captured in incident-context.json.
#
# This test:
#   - does NOT query Windows
#   - does NOT open the dump
#   - does NOT interpret the bugcheck
#   - does NOT infer root cause
#
# It reconstructs the relationship:
#
# BugCheck Event
#     -> ProducedDiagnosticArtifact
#     -> Windows Minidump
# ============================================================


# ------------------------------------------------------------
# TEST INPUT
# ------------------------------------------------------------

$RunDirectory = `
    "C:\Dev\halon\output\WADESYSTEM_20260829_091900"

$IncidentContextPath = `
    Join-Path `
        $RunDirectory `
        "incident-context.json"

$EventsPath = `
    Join-Path `
        $RunDirectory `
        "events.json"

# ------------------------------------------------------------
# VALIDATE INPUT
# ------------------------------------------------------------

if (-not (Test-Path $IncidentContextPath)) {

    throw (
        "HALON incident context not found: {0}" -f `
            $IncidentContextPath
    )
}

if (-not (Test-Path $EventsPath)) {

    throw (
        "HALON canonical events not found: {0}" -f `
            $EventsPath
    )
}

# ------------------------------------------------------------
# LOAD INCIDENT CONTEXT
# ------------------------------------------------------------

$IncidentContext = @(
    Get-Content `
        $IncidentContextPath `
        -Raw |
        ConvertFrom-Json
)

$EventsDocument = `
    Get-Content `
        $EventsPath `
        -Raw |
        ConvertFrom-Json


$Events = @(
    foreach ($EventRecord in $EventsDocument) {

        $EventRecord
    }
)

# ------------------------------------------------------------
# FIND BUGCHECK EVIDENCE
# ------------------------------------------------------------

$BugCheckEvents = @(
    $IncidentContext |
        ForEach-Object {

            $Incident = $_

            @($Incident.Events) |
                Where-Object {

                    $_.EventID -eq 1001 -and
                    $_.Provider -eq `
                        "Microsoft-Windows-WER-SystemErrorReporting"
                }
        }
)


Write-Host ""
Write-Host "========================================"
Write-Host " HALON DIAGNOSTIC ARTIFACT TEST"
Write-Host "========================================"
Write-Host ""

Write-Host (
    "BugCheck evidence records found: {0}" -f `
        $BugCheckEvents.Count
)


if ($BugCheckEvents.Count -eq 0) {

    throw (
        "FAIL: No BugCheck Event 1001 evidence was found."
    )
}


# ------------------------------------------------------------
# RECONSTRUCT DIAGNOSTIC ARTIFACTS
# ------------------------------------------------------------

$DiagnosticArtifacts = @()


foreach ($IncidentEvent in $BugCheckEvents) {

    # --------------------------------------------------------
    # RESOLVE CANONICAL SOURCE EVENT
    #
    # incident-context.json establishes that this BugCheck
    # belongs to the reconstructed incident.
    #
    # events.json retains the complete normalized event,
    # including StructuredEventData.
    #
    # RecordId is the deterministic bridge between them.
    # --------------------------------------------------------

    $SourceEvent = $null


    foreach ($CandidateEvent in $Events) {

        if (
            [string]$CandidateEvent.RecordId -eq
            [string]$IncidentEvent.RecordId
        ) {

            $SourceEvent = `
                $CandidateEvent

            break
        }
    }

    if ($null -eq $SourceEvent) {

        Write-Host (
            "WARN: Incident BugCheck RecordId {0} " +
            "could not be resolved in events.json." -f `
                $IncidentEvent.RecordId
        )

        continue
    }


    $StructuredData = `
        $SourceEvent.StructuredEventData


    if ($null -eq $StructuredData) {

        Write-Host (
            "WARN: Canonical BugCheck RecordId {0} " +
            "has no StructuredEventData." -f `
                $SourceEvent.RecordId
        )

        continue
    }


    # Current normalized WER Event 1001 representation:
    #
    # param1 = raw BugCheck tuple
    # param2 = Windows dump path
    # param3 = Windows report ID
    #
    # HALON treats these as observed values only.

    $BugCheckRaw = `
        $StructuredData.param1

    $DumpPath = `
        $StructuredData.param2

    $ReportId = `
        $StructuredData.param3


    if (
        [string]::IsNullOrWhiteSpace(
            [string]$DumpPath
        )
    ) {

        continue
    }


    $ArtifactType = `
        "UnknownDiagnosticArtifact"


    if (
        [System.IO.Path]::GetExtension(
            [string]$DumpPath
        ) -ieq ".dmp"
    ) {

        $ArtifactType = `
            "WindowsMinidump"
    }


    $DiagnosticArtifacts += `
        [PSCustomObject]@{

            Relationship = `
                "ProducedDiagnosticArtifact"


            ArtifactType = `
                $ArtifactType

            ArtifactPath = `
                [string]$DumpPath

            ReportId = `
                [string]$ReportId

            BugCheckRaw = `
                [string]$BugCheckRaw


            EvidenceSource = `
                [PSCustomObject]@{

                    RecordId = `
                        $SourceEvent.RecordId

                    EventID = `
                        $SourceEvent.EventID

                    Provider = `
                        $SourceEvent.Provider

                    OccurrenceTime = `
                        $SourceEvent.OccurrenceTime

                    LoggedTime = `
                        $SourceEvent.LoggedTime
                }


            IncidentAssociation = `
                [PSCustomObject]@{

                    RecordId = `
                        $IncidentEvent.RecordId

                    EventID = `
                        $IncidentEvent.EventID

                    Provider = `
                        $IncidentEvent.Provider

                    EvidenceBasis = `
                        "IncidentContextRecordIdMatch"
                }


            EvidenceBasis = `
                "CanonicalEventStructuredData"
        }
}


# ------------------------------------------------------------
# VALIDATE RECONSTRUCTION
# ------------------------------------------------------------

if ($DiagnosticArtifacts.Count -eq 0) {

    throw (
        "FAIL: BugCheck evidence was found, but no diagnostic " +
        "artifact could be reconstructed."
    )
}


$ExpectedArtifact = `
    $DiagnosticArtifacts |
        Where-Object {

            $_.ArtifactPath -like `
                "*082926-15156-01.dmp"
        } |
        Select-Object -First 1


if ($null -eq $ExpectedArtifact) {

    throw (
        "FAIL: Expected Windows minidump was not reconstructed."
    )
}


if (
    $ExpectedArtifact.EvidenceSource.RecordId `
        -ne 143142
) {

    throw (
        "FAIL: Diagnostic artifact lost its source evidence " +
        "Record ID."
    )
}


# ------------------------------------------------------------
# RESULT
# ------------------------------------------------------------

Write-Host ""
Write-Host "Reconstruction: PASS"
Write-Host ""

$ExpectedArtifact |
    ConvertTo-Json -Depth 10

Write-Host ""
Write-Host "========================================"
Write-Host " CAPABILITY PROVEN"
Write-Host "========================================"
Write-Host ""