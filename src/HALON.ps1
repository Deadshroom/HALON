$ErrorActionPreference = "Stop"

# ---------------------------------------------
# LOAD HALON COMPONENTS
# ---------------------------------------------

. "$PSScriptRoot\core\Halon.Common.ps1"
# Collectors
. "$PSScriptRoot\collectors\Halon.HostCollector.ps1"
. "$PSScriptRoot\collectors\Halon.EventCollector.ps1"
. "$PSScriptRoot\collectors\Halon.IdentityCollector.ps1"
. "$PSScriptRoot\collectors\Halon.SessionCollector.ps1"
. "$PSScriptRoot\collectors\Halon.ProcessCollector.ps1"
# Normalizers
. "$PSScriptRoot\normalizers\Halon.EventNormalizer.ps1"
. "$PSScriptRoot\normalizers\Halon.IdentityNormalizer.ps1"
. "$PSScriptRoot\normalizers\Halon.SessionNormalizer.ps1"
. "$PSScriptRoot\normalizers\Halon.ProcessNormalizer.ps1"
# Reconstructors
. "$PSScriptRoot\reconstructors\Halon.IdentitySessionReconstructor.ps1"
. "$PSScriptRoot\reconstructors\Halon.WindowsSessionReconstructor.ps1"
. "$PSScriptRoot\reconstructors\Halon.TimelineReconstructor.ps1"
. "$PSScriptRoot\reconstructors\Halon.IncidentReconstructor.ps1"
. "$PSScriptRoot\reconstructors\Halon.ProcessTreeReconstructor.ps1"
# Correlators
. "$PSScriptRoot\correlators\Halon.ProcessLogonCorrelator.ps1"
. "$PSScriptRoot\correlators\Halon.EventProcessCorrelator.ps1"
. "$PSScriptRoot\correlators\Halon.IncidentIdentityCorrelator.ps1"
. "$PSScriptRoot\correlators\Halon.IncidentSessionCorrelator.ps1"
. "$PSScriptRoot\correlators\Halon.ProcessIdentitySessionCorrelator.ps1"
# Builder
. "$PSScriptRoot\builders\Halon.SummaryBuilder.ps1"
. "$PSScriptRoot\builders\Halon.ManifestBuilder.ps1"

. "$PSScriptRoot\instrumentation\Halon.Performance.ps1"
# Exporter
. "$PSScriptRoot\exporters\Halon.EvidenceExporter.ps1"
. "$PSScriptRoot\exporters\Halon.JsonExporter.ps1"

# ---------------------------------------------
# HALON
# Portable Windows Incident Diagnostic
# Version 0.1
# ---------------------------------------------

$HalonRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

$ComputerName = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$StartTime = (Get-Date).AddHours(-24)

$RunDirectory = Join-Path `
    $HalonRoot `
    "output\$ComputerName`_$Timestamp"

New-Item `
    -ItemType Directory `
    -Path $RunDirectory `
    -Force | Out-Null

# ---------------------------------------------
# PERFORMANCE INSTRUMENTATION
# ---------------------------------------------

$HalonRunStopwatch = `
    [System.Diagnostics.Stopwatch]::StartNew()

$PerformanceMetrics = `
    [System.Collections.Generic.List[object]]::new()

# ---------------------------------------------
# PROCESS CREATION AUDIT CAPABILITY
# ---------------------------------------------

$ProcessAuditCapability = `
    Get-HalonProcessAuditCapability

Write-Host ""
Write-Host "======================================="
Write-Host " HALON"
Write-Host " Portable Windows Incident Diagnostic"
Write-Host "======================================="
Write-Host ""
Write-Host "Host:             $ComputerName"
Write-Host "Collection Start: $StartTime"
Write-Host "Administrator:    $(Test-IsAdministrator)"
Write-Host ""

# ---------------------------------------------
# SYSTEM INFORMATION
# ---------------------------------------------
$SystemInfo = Get-HalonSystemInformation `
    -ComputerName $ComputerName
$SystemInfo |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        (Join-Path $RunDirectory "system-info.json") `
        -Encoding UTF8

# ---------------------------------------------
# DISK INFORMATION
# ---------------------------------------------

$Disks = Get-HalonDiskInformation
Write-HalonJsonArray `
    -InputObject $Disks `
    -Path (Join-Path $RunDirectory "disks.json") `
    -Depth 4

# ---------------------------------------------
# SERVICES
# ---------------------------------------------
$Services = Get-HalonServiceInformation
Write-HalonJsonArray `
    -InputObject $Services `
    -Path (Join-Path $RunDirectory "services.json") `
    -Depth 4

# ---------------------------------------------
# WINDOWS EVENT LOGS
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer

$RawEvents = Get-HalonWindowsEventEvidence `
    -StartTime $StartTime

Complete-HalonStageTimer `
    -Stage "Event.Collection" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($RawEvents).Count

# Normalize Windows events into HALON's internal structure.

$StageTimer = Start-HalonStageTimer

$Events = ConvertTo-HalonEventEvidence `
    -RawEvents $RawEvents

Complete-HalonStageTimer `
    -Stage "Event.Normalization" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($Events).Count

Write-HalonJsonArray `
    -InputObject $Events `
    -Path (Join-Path $RunDirectory "events.json") `
    -Depth 5

# ---------------------------------------------
# IDENTITY / SESSION EVIDENCE
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer

$IdentityCollection = Get-HalonIdentityEvidence `
    -StartTime $StartTime

Complete-HalonStageTimer `
    -Stage "Identity.Collection" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($IdentityCollection.Events).Count

$IdentityEventsRaw = @($IdentityCollection.Events)

$IdentityCollectionStatus = `
    $IdentityCollection.Status

$IdentityCollectionError = `
    $IdentityCollection.Error

# ---------------------------------------------
# PROCESS CREATION EVIDENCE
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer


$ProcessCollection = `
    Get-HalonProcessCreationEvidence `
        -StartTime $StartTime


$ProcessCreationEventsRaw = `
    $ProcessCollection.Events

Complete-HalonStageTimer `
    -Stage "Process.Collection" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($ProcessCreationEventsRaw).Count

# ---------------------------------------------
# NORMALIZE PROCESS CREATION EVIDENCE
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer


$ProcessCreationEvents = `
    ConvertTo-HalonProcessCreationEvidence `
        -RawEvents $ProcessCreationEventsRaw


Complete-HalonStageTimer `
    -Stage "Process.Normalization" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($ProcessCreationEvents).Count

# ---------------------------------------------
# PROCESS TREE RECONSTRUCTION
# ---------------------------------------------

$StageTimer = Start-HalonStageTimer


$ProcessTree = `
    Get-HalonProcessTree `
        -ProcessCreationEvents $ProcessCreationEvents


Complete-HalonStageTimer `
    -Stage "Process.TreeReconstruction" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($ProcessTree).Count

# ---------------------------------------------
# PROCESS LINEAGE RECONSTRUCTION
# ---------------------------------------------

$StageTimer = Start-HalonStageTimer


$ProcessLineages = `
    Get-HalonProcessLineages `
        -ProcessTree $ProcessTree


Complete-HalonStageTimer `
    -Stage "Process.LineageReconstruction" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($ProcessLineages).Count

# ---------------------------------------------
# WRITE PROCESS CREATION EVIDENCE
# ---------------------------------------------

$ProcessCreationEventExport = @(
    ConvertTo-HalonProcessCreationExport `
        -ProcessCreationEvents $ProcessCreationEvents
)

Write-HalonJsonArray `
    -InputObject $ProcessCreationEventExport `
    -Path (Join-Path $RunDirectory "process-events.json") `
    -Depth 6

# ---------------------------------------------
# WRITE PROCESS LINEAGE EVIDENCE
# ---------------------------------------------

$ProcessLineageExport = @(
    ConvertTo-HalonProcessLineageExport `
        -ProcessLineages $ProcessLineages
)

Write-HalonJsonArray `
    -InputObject $ProcessLineageExport `
    -Path (Join-Path $RunDirectory "process-lineage.json") `
    -Depth 8


# ---------------------------------------------
# PROCESS EVIDENCE CAPABILITY
# ---------------------------------------------

$ProcessEvidenceCapability = `
    New-HalonProcessEvidenceCapability `
        -AuditCapability $ProcessAuditCapability `
        -ProcessCollection $ProcessCollection `
        -ProcessCreationEvents $ProcessCreationEvents


$ProcessEvidenceCapability |
    ConvertTo-Json -Depth 5 |
    Set-Content `
        (Join-Path $RunDirectory "process-evidence-capability.json") `
        -Encoding UTF8

# ---------------------------------------------
# NORMALIZE IDENTITY EVENTS
# ---------------------------------------------

$StageTimer = Start-HalonStageTimer

$IdentityEvents = ConvertTo-HalonIdentityEvidence `
    -RawEvents $IdentityEventsRaw

Complete-HalonStageTimer `
    -Stage "Identity.Normalization" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($IdentityEvents).Count

# ---------------------------------------------
# RECONSTRUCT INTERACTIVE USER SESSIONS
# ---------------------------------------------

$StageTimer = Start-HalonStageTimer

$IdentitySessions = `
    Get-HalonIdentitySessions `
        -IdentityEvents $IdentityEvents

Complete-HalonStageTimer `
    -Stage "Identity.Reconstruction" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($IdentitySessions).Count

# ---------------------------------------------
# WRITE RECONSTRUCTED IDENTITY SESSIONS
# ---------------------------------------------

$IdentitySessionExport = @(
    ConvertTo-HalonIdentitySessionExport `
        -IdentitySessions $IdentitySessions
)


Write-HalonJsonArray `
    -InputObject $IdentitySessionExport `
    -Path (Join-Path $RunDirectory "identity-sessions.json") `
    -Depth 6

# ---------------------------------------------
# CURRENT WINDOWS SESSION SNAPSHOT
# ---------------------------------------------

$CurrentSessions = `
    Get-HalonCurrentSessionSnapshot

# ---------------------------------------------
# WRITE CURRENT SESSION SNAPSHOT
# ---------------------------------------------

Write-HalonJsonArray `
    -InputObject $CurrentSessions `
    -Path (Join-Path $RunDirectory "current-sessions.json") `
    -Depth 5

# ---------------------------------------------
# WINDOWS SESSION LIFECYCLE EVIDENCE
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer

$WindowsSessionCollection = `
    Get-HalonWindowsSessionEvidence `
        -StartTime $StartTime
Complete-HalonStageTimer `
    -Stage "Session.Collection" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($WindowsSessionCollection.Events).Count

$WindowsSessionEventsRaw = @(
    $WindowsSessionCollection.Events
)


$WindowsSessionCollectionStatus = `
    $WindowsSessionCollection.Status


$WindowsSessionCollectionError = `
    $WindowsSessionCollection.Error

# ---------------------------------------------
# NORMALIZE WINDOWS SESSION LIFECYCLE EVENTS
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer

$WindowsSessionEvents = `
    ConvertTo-HalonWindowsSessionEvidence `
        -RawEvents $WindowsSessionEventsRaw

Complete-HalonStageTimer `
    -Stage "Session.Normalization" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($WindowsSessionEvents).Count
# ---------------------------------------------
# WRITE WINDOWS SESSION LIFECYCLE EVIDENCE
# ---------------------------------------------

Write-HalonJsonArray `
    -InputObject $WindowsSessionEvents `
    -Path (
        Join-Path `
            $RunDirectory `
            "windows-session-events.json"
    ) `
    -Depth 8

# ---------------------------------------------
# RECONSTRUCT WINDOWS SESSIONS
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer

$WindowsSessions = `
    Get-HalonWindowsSessions `
        -WindowsSessionEvents $WindowsSessionEvents

Complete-HalonStageTimer `
    -Stage "Session.Reconstruction" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($WindowsSessions).Count

# ---------------------------------------------
# WRITE RECONSTRUCTED WINDOWS SESSIONS
# ---------------------------------------------

$WindowsSessionExport = @(
    ConvertTo-HalonWindowsSessionExport `
        -WindowsSessions $WindowsSessions
)

Write-HalonJsonArray `
    -InputObject $WindowsSessionExport `
    -Path (Join-Path $RunDirectory "windows-sessions.json") `
    -Depth 8
# ---------------------------------------------
# WRITE IDENTITY EVIDENCE
# ---------------------------------------------

Write-HalonJsonArray `
    -InputObject $IdentityEvents `
    -Path (Join-Path $RunDirectory "identity-events.json") `
    -Depth 6

# ---------------------------------------------
# PROCESS / LOGON CONTEXT CORRELATION
# ---------------------------------------------

# ---------------------------------------------
# BUILD LOGON INDEX
# ---------------------------------------------

$StageTimer = Start-HalonStageTimer

$LogonIndex = New-HalonLogonIndex `
    -IdentityEvents $IdentityEvents

Complete-HalonStageTimer `
    -Stage "Correlation.LogonIndexBuild" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount $LogonIndex.Count


# ---------------------------------------------
# PROCESS / LOGON CORRELATION
# ---------------------------------------------

$StageTimer = Start-HalonStageTimer

$ProcessLogonContexts = `
    Get-HalonProcessLogonCorrelations `
        -ProcessCreationEvents $ProcessCreationEvents `
        -LogonIndex $LogonIndex

Complete-HalonStageTimer `
    -Stage "Correlation.ProcessToLogon" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($ProcessLogonContexts).Count

# ---------------------------------------------
# PROCESS EXECUTION CONTEXT
# ---------------------------------------------

$StageTimer = Start-HalonStageTimer


$ProcessExecutionContexts = `
    Get-HalonProcessExecutionContexts `
        -ProcessLineages $ProcessLineages `
        -ProcessLogonContexts $ProcessLogonContexts `
        -WindowsSessions $WindowsSessions


Complete-HalonStageTimer `
    -Stage "Correlation.ProcessIdentitySession" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($ProcessExecutionContexts).Count

# ---------------------------------------------
# WRITE PROCESS EXECUTION CONTEXT
# ---------------------------------------------

$ProcessExecutionContextExport = @(
    ConvertTo-HalonProcessExecutionContextExport `
        -ProcessExecutionContexts $ProcessExecutionContexts
)

Write-HalonJsonArray `
    -InputObject $ProcessExecutionContextExport `
    -Path (
        Join-Path `
            $RunDirectory `
            "process-execution-contexts.json"
    ) `
    -Depth 10
# ---------------------------------------------
# WRITE PROCESS / LOGON CONTEXT
# ---------------------------------------------

$ProcessLogonContextExport = @(
    ConvertTo-HalonProcessLogonContextExport `
        -ProcessLogonContexts $ProcessLogonContexts
)


Write-HalonJsonArray `
    -InputObject $ProcessLogonContextExport `
    -Path (Join-Path $RunDirectory "process-logon-contexts.json") `
    -Depth 6

# ---------------------------------------------
# EVENT PROCESS REFERENCES
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer


$EventProcessReferences = @(
    Get-HalonEventProcessReferences `
        -Events $Events
)


Complete-HalonStageTimer `
    -Stage "Correlation.EventReferences" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($EventProcessReferences).Count


# ---------------------------------------------
# EVENT / HISTORICAL PROCESS CORRELATION
# ---------------------------------------------

$StageTimer = Start-HalonStageTimer


$EventProcessCorrelations = @(
    Get-HalonEventProcessCorrelations `
        -EventProcessReferences $EventProcessReferences `
        -ProcessLogonContexts $ProcessLogonContexts
)


Complete-HalonStageTimer `
    -Stage "Correlation.EventToProcess" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($EventProcessCorrelations).Count
# ---------------------------------------------
# EVENT / HISTORICAL PROCESS CORRELATION
# ---------------------------------------------
$StageTimer = Start-HalonStageTimer
Write-Host "Correlating events with historical processes..."

$EventProcessCorrelations = @()


foreach ($Reference in $EventProcessReferences) {

    $EventTime = [datetime]$Reference.EventTime


    $PossibleMatches = $ProcessLogonContexts |
        Where-Object {

            [datetime]$_.ProcessTime -le $EventTime -and

            $_.ProcessId -eq `
                $Reference.ReferencedProcessId
        }


    # -----------------------------------------
    # Require process-name/path agreement
    # whenever the event supplied one.
    # -----------------------------------------

    if (
        -not [string]::IsNullOrWhiteSpace(
            $Reference.ReferencedProcessName
        )
    ) {

        $PossibleMatches = $PossibleMatches |
            Where-Object {

                $HistoricalName = `
                    [System.IO.Path]::GetFileName(
                        $_.ProcessName
                    )

                $HistoricalName -ieq `
                    $Reference.ReferencedProcessName
            }
    }


    # PID reuse is possible.
    # The most recent compatible process creation
    # before the event is the relevant historical
    # process record.

    $MatchingProcess = $PossibleMatches |
        Sort-Object ProcessTime -Descending |
        Select-Object -First 1


    if ($null -ne $MatchingProcess) {

        $ProcessMatchFound = $true

        $ProcessCreated = `
            $MatchingProcess.ProcessTime

        $ProcessAgeSeconds = [math]::Round(
            (
                $EventTime -
                [datetime]$MatchingProcess.ProcessTime
            ).TotalSeconds,
            3
        )


        if (
            -not [string]::IsNullOrWhiteSpace(
                $Reference.ReferencedProcessName
            )
        ) {

            $MatchBasis = "ProcessIdAndProcessName"

        }
        else {

            $MatchBasis = "ProcessIdOnly"
        }
    }
    else {

        $ProcessMatchFound = $false
        $ProcessCreated    = $null
        $ProcessAgeSeconds = $null
        $MatchBasis        = "NoHistoricalProcessMatch"
    }


    $EventProcessCorrelations += [PSCustomObject]@{

        # EVENT SIDE

        EventTime     = $Reference.EventTime
        EventRecordId = $Reference.EventRecordId

        EventProvider = $Reference.EventProvider
        EventID       = $Reference.EventID
        EventLevel    = $Reference.EventLevel


        ReferencedProcessId = `
            $Reference.ReferencedProcessId

        ReferencedProcessName = `
            $Reference.ReferencedProcessName

        ReferencedProcessPath = `
            $Reference.ReferencedProcessPath


        # CORRELATION

        HistoricalProcessFound = `
            $ProcessMatchFound

        MatchBasis = `
            $MatchBasis

        ProcessAgeAtEventSeconds = `
            $ProcessAgeSeconds


        # HISTORICAL PROCESS SIDE

        HistoricalProcessCreated = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.ProcessTime

        }
        else {

            $null
        }


        HistoricalProcessName = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.ProcessName

        }
        else {

            $null
        }


        ParentProcessName = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.ParentProcessName

        }
        else {

            $null
        }


        ParentProcessId = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.ParentProcessId

        }
        else {

            $null
        }


        # IDENTITY SIDE

        SubjectIdentity = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.SubjectIdentity

        }
        else {

            $null
        }


        SubjectUserSid = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.SubjectUserSid

        }
        else {

            $null
        }


        SubjectLogonId = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.SubjectLogonId

        }
        else {

            $null
        }


        LogonContextFound = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.LogonContextFound

        }
        else {

            $false
        }


        LogonIdentity = if (
            $ProcessMatchFound
        ) {

            $MatchingProcess.LogonIdentity

        }
        else {

            $null
        }


        EvidenceBasis = if (
            $ProcessMatchFound
        ) {

            "WindowsEventProcessReference+" +
            "Security4688"

        }
        else {

            "WindowsEventProcessReferenceOnly"
        }
    }
}
Complete-HalonStageTimer `
    -Stage "Correlation.EventToProcess" `
    -Stopwatch $StageTimer `
    -Metrics $PerformanceMetrics `
    -ItemCount @($EventProcessCorrelations).Count
# ---------------------------------------------
# WRITE EVENT / PROCESS CORRELATION
# ---------------------------------------------

$EventProcessCorrelationExport = @(
    ConvertTo-HalonEventProcessCorrelationExport `
        -EventProcessCorrelations $EventProcessCorrelations
)
# ---------------------------------------------
# GUARANTEED EVENT / PROCESS CORRELATION EXPORT
# ---------------------------------------------

Write-Host "Event process references found: $(@($EventProcessReferences).Count)"
Write-Host "Event/process correlations built: $(@($EventProcessCorrelations).Count)"

Write-HalonJsonArray `
    -InputObject $EventProcessCorrelationExport `
    -Path (
        Join-Path `
            $RunDirectory `
            "event-process-correlations.json"
    ) `
    -Depth 7

# ---------------------------------------------
# EVIDENCE CATEGORY SUMMARY
# ---------------------------------------------

$EvidenceSummary = @(
    Get-HalonEvidenceSummary `
        -Events $Events
)

Write-HalonJsonArray `
    -InputObject $EvidenceSummary `
    -Path (Join-Path $RunDirectory "evidence-summary.json") `
    -Depth 4
# ---------------------------------------------
# TIMELINE RECONSTRUCTION
# ---------------------------------------------

$Timeline = Get-HalonTimeline `
    -Events $Events

$TimelineExport = @(
    ConvertTo-HalonTimelineExport `
        -Timeline $Timeline
)


Write-HalonJsonArray `
    -InputObject $TimelineExport `
    -Path (Join-Path $RunDirectory "timeline.json") `
    -Depth 5

# ---------------------------------------------
# INCIDENT RECONSTRUCTION
# ---------------------------------------------

$IncidentAnchors = `
    Get-HalonIncidentAnchors `
        -Timeline $Timeline


$IncidentContexts = `
    Get-HalonIncidentContexts `
        -Timeline $Timeline `
        -IncidentAnchors $IncidentAnchors


Write-HalonJsonArray `
    -InputObject $IncidentContexts `
    -Path (Join-Path $RunDirectory "incident-context.json") `
    -Depth 10

# ---------------------------------------------
# INCIDENT IDENTITY CORRELATION
# ---------------------------------------------
$IncidentIdentityContexts = `
    Get-HalonIncidentIdentityContexts `
        -IncidentAnchors $IncidentAnchors `
        -IdentitySessions $IdentitySessions `
        -IdentityCollectionStatus $IdentityCollectionStatus `
        -CollectionWindowStart $StartTime


Write-HalonJsonArray `
    -InputObject $IncidentIdentityContexts `
    -Path (Join-Path $RunDirectory "incident-identities.json") `
    -Depth 8

# ---------------------------------------------
# WINDOWS SESSION / INCIDENT CORRELATION
# ---------------------------------------------

$WindowsSessionIncidentContexts = `
    Get-HalonIncidentWindowsSessionContexts `
        -IncidentAnchors $IncidentAnchors `
        -WindowsSessions $WindowsSessions `
        -CollectionWindowStart $StartTime


Write-HalonJsonArray `
    -InputObject $WindowsSessionIncidentContexts `
    -Path (
        Join-Path `
            $RunDirectory `
            "windows-sessions-at-incident.json"
    ) `
    -Depth 8

# ---------------------------------------------
# INCIDENT WINDOWS
# ---------------------------------------------

$IncidentWindows = `
    Get-HalonIncidentWindows `
        -Timeline $Timeline `
        -IncidentAnchors $IncidentAnchors


# ---------------------------------------------
# INCIDENT JSON EXPORT
# ---------------------------------------------

$IncidentExport = @(
    ConvertTo-HalonIncidentExport `
        -IncidentWindows $IncidentWindows
)

Write-HalonJsonArray `
    -InputObject $IncidentExport `
    -Path (Join-Path $RunDirectory "incidents.json") `
    -Depth 10

# ---------------------------------------------
# EVENT PATTERN SUMMARY
# ---------------------------------------------

$EventSummary = @(
    Get-HalonEventSummary `
        -Events $Events
)

Write-HalonJsonArray `
    -InputObject $EventSummary `
    -Path (Join-Path $RunDirectory "event-summary.json") `
    -Depth 4


# ---------------------------------------------
# RUN MANIFEST
# ---------------------------------------------

$Manifest = `
    New-HalonRunManifest `
        -ComputerName $ComputerName `
        -CollectionStart $StartTime `
        -OutputDirectory $RunDirectory `
        -Events $Events `
        -IdentityCollection $IdentityCollection `
        -WindowsSessionCollection $WindowsSessionCollection `
        -ProcessAuditCapability $ProcessAuditCapability `
        -ProcessCollection $ProcessCollection `
        -ProcessCreationEvents $ProcessCreationEvents


$Manifest |
    ConvertTo-Json |
    Set-Content `
        (Join-Path $RunDirectory "manifest.json") `
        -Encoding UTF8

Write-HalonPerformanceReport `
    -Metrics $PerformanceMetrics `
    -RunStopwatch $HalonRunStopwatch `
    -Path (
        Join-Path `
            $RunDirectory `
            "performance.json"
    )
    
Write-Host ""
Write-Host "======================================="
Write-Host " HALON COLLECTION COMPLETE"
Write-Host "======================================="
Write-Host ""
Write-Host "Events collected: $($Events.Count)"
Write-Host "Evidence directory:"
Write-Host $RunDirectory
Write-Host ""