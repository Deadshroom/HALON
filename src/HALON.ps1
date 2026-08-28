$ErrorActionPreference = "Stop"

# ---------------------------------------------
# LOAD HALON COMPONENTS
# ---------------------------------------------

. "$PSScriptRoot\core\Halon.Common.ps1"

. "$PSScriptRoot\collectors\Halon.HostCollector.ps1"
. "$PSScriptRoot\collectors\Halon.EventCollector.ps1"
. "$PSScriptRoot\collectors\Halon.IdentityCollector.ps1"
. "$PSScriptRoot\collectors\Halon.SessionCollector.ps1"
. "$PSScriptRoot\collectors\Halon.ProcessCollector.ps1"

. "$PSScriptRoot\normalizers\Halon.EventNormalizer.ps1"
. "$PSScriptRoot\normalizers\Halon.IdentityNormalizer.ps1"
. "$PSScriptRoot\normalizers\Halon.SessionNormalizer.ps1"
. "$PSScriptRoot\normalizers\Halon.ProcessNormalizer.ps1"

. "$PSScriptRoot\reconstructors\Halon.IdentitySessionReconstructor.ps1"
. "$PSScriptRoot\reconstructors\Halon.WindowsSessionReconstructor.ps1"
. "$PSScriptRoot\reconstructors\Halon.TimelineReconstructor.ps1"
. "$PSScriptRoot\reconstructors\Halon.IncidentReconstructor.ps1"

. "$PSScriptRoot\correlators\Halon.ProcessLogonCorrelator.ps1"
. "$PSScriptRoot\correlators\Halon.EventProcessCorrelator.ps1"
. "$PSScriptRoot\correlators\Halon.IncidentIdentityCorrelator.ps1"
. "$PSScriptRoot\correlators\Halon.IncidentSessionCorrelator.ps1"

. "$PSScriptRoot\instrumentation\Halon.Performance.ps1"

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

$ProcessCreationAuditPolicy  = "Unknown"
$ProcessCreationAuditEnabled = $false
$ProcessCreationAuditError   = $null


try {

    $AuditPolicyRaw = auditpol `
        /get `
        /subcategory:"Process Creation" `
        /r

    if ($LASTEXITCODE -eq 0 -and $AuditPolicyRaw) {

        try {

            $AuditPolicyData = $AuditPolicyRaw |
                ConvertFrom-Csv |
                Select-Object -First 1


            $InclusionSetting = $AuditPolicyData.'Inclusion Setting'


            if (
                -not [string]::IsNullOrWhiteSpace(
                    $InclusionSetting
                )
            ) {

                $ProcessCreationAuditPolicy = `
                    $InclusionSetting


                if (
                    $InclusionSetting -match "Success"
                ) {

                    $ProcessCreationAuditEnabled = $true
                }
            }
        }
        catch {

            $ProcessCreationAuditPolicy = "Unknown"
            $ProcessCreationAuditError  = `
                "HALON could not parse auditpol output."
        }
    }
}
catch {

    $ProcessCreationAuditPolicy = "Unknown"
    $ProcessCreationAuditError  = $_.Exception.Message
}

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


$ProcessCreationEvidenceStatus = `
    $ProcessCollection.Status


$ProcessCreationEvidenceError = `
    $ProcessCollection.Error


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
# WRITE PROCESS CREATION EVIDENCE
# ---------------------------------------------

$ProcessCreationEventExport = $ProcessCreationEvents |
    ForEach-Object {

        [PSCustomObject]@{

            TimeCreated = (
                [datetime]$_.TimeCreated
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )

            SecurityRecordId = `
                $_.SecurityRecordId

            EventID = `
                $_.EventID


            SubjectIdentity = `
                $_.SubjectIdentity

            SubjectUserSid = `
                $_.SubjectUserSid

            SubjectLogonId = `
                $_.SubjectLogonId


            ProcessIdRaw = `
                $_.ProcessIdRaw

            ProcessIdDecimal = `
                $_.ProcessIdDecimal

            ProcessName = `
                $_.ProcessName


            ParentProcessIdRaw = `
                $_.ParentProcessIdRaw

            ParentProcessIdDecimal = `
                $_.ParentProcessIdDecimal

            ParentProcessName = `
                $_.ParentProcessName


            TargetIdentity = `
                $_.TargetIdentity

            TargetUserSid = `
                $_.TargetUserSid

            TargetLogonId = `
                $_.TargetLogonId


            CommandLine = `
                $_.CommandLine

            TokenElevationType = `
                $_.TokenElevationType

            MandatoryLabel = `
                $_.MandatoryLabel
        }
    }


Write-HalonJsonArray `
    -InputObject $ProcessCreationEventExport `
    -Path (Join-Path $RunDirectory "process-events.json") `
    -Depth 6


# ---------------------------------------------
# PROCESS EVIDENCE CAPABILITY
# ---------------------------------------------

$ProcessEvidenceCapability = [PSCustomObject]@{

    AuditSubcategory = "Process Creation"

    CurrentAuditPolicy = `
        $ProcessCreationAuditPolicy

    SuccessAuditingEnabled = `
        $ProcessCreationAuditEnabled

    AuditPolicyDetectionError = `
        $ProcessCreationAuditError

    Historical4688Status = `
        $ProcessCreationEvidenceStatus

    Historical4688EventsCollected = @(
        $ProcessCreationEvents
    ).Count

    Historical4688CollectionError = `
        $ProcessCreationEvidenceError
}


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

$IdentitySessionExport = $IdentitySessions |
    ForEach-Object {

        [PSCustomObject]@{

            Identity = $_.Identity
            IdentityClass = $_.IdentityClass
            UserName = $_.UserName
            Domain   = $_.Domain
            UserSid  = $_.UserSid
            LogonId   = $_.LogonId
            LogonType = $_.LogonType

            SessionStart = (
                [datetime]$_.SessionStart
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )

            SessionEnd = if ($null -ne $_.SessionEnd) {

                (
                    [datetime]$_.SessionEnd
                ).ToString(
                    "MM/dd/yyyy HH:mm:ss"
                )

            }
            else {
                $null
            }

            DurationMinutes = $_.DurationMinutes

            State     = $_.State
            EndReason = $_.EndReason

            LogonRecordId  = $_.LogonRecordId
            LogoffRecordId = $_.LogoffRecordId
        }
    }


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

$WindowsSessionExport = $WindowsSessions |
    ForEach-Object {

        [PSCustomObject]@{

            User = $_.User

            SessionId = $_.SessionId

            SourceAddress = $_.SourceAddress

            SessionStart = (
                [datetime]$_.SessionStart
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )

            SessionEnd = if ($null -ne $_.SessionEnd) {

                (
                    [datetime]$_.SessionEnd
                ).ToString(
                    "MM/dd/yyyy HH:mm:ss"
                )

            }
            else {
                $null
            }

            State = $_.State

            LogonRecordId  = $_.LogonRecordId
            LogoffRecordId = $_.LogoffRecordId

            StateEvents = @(
                $_.StateEvents |
                    ForEach-Object {

                        [PSCustomObject]@{

                            TimeCreated = (
                                [datetime]$_.TimeCreated
                            ).ToString(
                                "MM/dd/yyyy HH:mm:ss"
                            )

                            Action   = $_.Action
                            RecordId = $_.RecordId
                        }
                    }
            )
        }
    }


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
# WRITE PROCESS / LOGON CONTEXT
# ---------------------------------------------

$ProcessLogonContextExport = $ProcessLogonContexts |
    ForEach-Object {

        [PSCustomObject]@{

            ProcessTime = (
                [datetime]$_.ProcessTime
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )

            ProcessId = $_.ProcessId
            ProcessIdRaw = $_.ProcessIdRaw
            ProcessName = $_.ProcessName

            ParentProcessId = $_.ParentProcessId
            ParentProcessName = $_.ParentProcessName

            SubjectIdentity = $_.SubjectIdentity
            SubjectUserSid = $_.SubjectUserSid
            SubjectLogonId = $_.SubjectLogonId

            LogonContextFound = $_.LogonContextFound
            LogonIdentity = $_.LogonIdentity
            LogonUserSid = $_.LogonUserSid
            LogonType = $_.LogonType

            LogonTime = if ($null -ne $_.LogonTime) {

                (
                    [datetime]$_.LogonTime
                ).ToString(
                    "MM/dd/yyyy HH:mm:ss"
                )
            }
            else {
                $null
            }

            ProcessSecurityRecordId = `
                $_.ProcessSecurityRecordId

            LogonSecurityRecordId = `
                $_.LogonSecurityRecordId

            EvidenceBasis = $_.EvidenceBasis
        }
    }


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

$EventProcessCorrelationExport = `
    $EventProcessCorrelations |
    ForEach-Object {

        [PSCustomObject]@{

            EventTime = (
                [datetime]$_.EventTime
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )

            EventRecordId = $_.EventRecordId

            EventProvider = $_.EventProvider
            EventID       = $_.EventID
            EventLevel    = $_.EventLevel


            ReferencedProcessId = `
                $_.ReferencedProcessId

            ReferencedProcessName = `
                $_.ReferencedProcessName

            ReferencedProcessPath = `
                $_.ReferencedProcessPath


            HistoricalProcessFound = `
                $_.HistoricalProcessFound

            MatchBasis = `
                $_.MatchBasis

            ProcessAgeAtEventSeconds = `
                $_.ProcessAgeAtEventSeconds


            HistoricalProcessCreated = if (
                $null -ne $_.HistoricalProcessCreated
            ) {

                (
                    [datetime]$_.HistoricalProcessCreated
                ).ToString(
                    "MM/dd/yyyy HH:mm:ss"
                )
            }
            else {

                $null
            }


            HistoricalProcessName = `
                $_.HistoricalProcessName

            ParentProcessId = `
                $_.ParentProcessId

            ParentProcessName = `
                $_.ParentProcessName


            SubjectIdentity = `
                $_.SubjectIdentity

            SubjectUserSid = `
                $_.SubjectUserSid

            SubjectLogonId = `
                $_.SubjectLogonId


            LogonContextFound = `
                $_.LogonContextFound

            LogonIdentity = `
                $_.LogonIdentity


            EvidenceBasis = `
                $_.EvidenceBasis
        }
    }

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

Write-Host "Categorizing incident evidence..."

$EvidenceSummary = $Events |
    Group-Object Category |
    Sort-Object Count -Descending |
    ForEach-Object {

        [PSCustomObject]@{
            Category = $_.Name
            Count    = $_.Count
        }
    }


Write-HalonJsonArray `
    -InputObject $EvidenceSummary `
    -Path (Join-Path $RunDirectory "evidence-summary.json") `
    -Depth 4
# ---------------------------------------------
# TIMELINE RECONSTRUCTION
# ---------------------------------------------

$Timeline = Get-HalonTimeline `
    -Events $Events

    
$TimelineExport = $Timeline |
    ForEach-Object {

        [PSCustomObject]@{
            LoggedTime     = ([datetime]$_.LoggedTime).ToString("MM/dd/yyyy HH:mm:ss")
            OccurrenceTime = ([datetime]$_.OccurrenceTime).ToString("MM/dd/yyyy HH:mm:ss")
            LogName        = $_.LogName
            RecordId       = $_.RecordId
            Level          = $_.Level
            EventID        = $_.EventID
            Provider       = $_.Provider
            AnchorType     = $_.AnchorType
            Message        = $_.Message
            Category = $_.Category
            EventSignature          = $_.EventSignature
            SeverityScore           = $_.SeverityScore
            EventUserSid = `    $_.EventUserSid
            EventUser = `    $_.EventUser
            BootSessionId = $_.BootSessionId
            BootSessionActive = $_.BootSessionActive
            SecondsSincePreviousEvent = $_.SecondsSincePreviousEvent
        }
    }

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

$IncidentExport = $IncidentWindows |
    ForEach-Object {

        $Incident = $_


        $ExportEvents = $Incident.Events |
            ForEach-Object {

                [PSCustomObject]@{

                    OccurrenceTime = (
                        [datetime]$_.OccurrenceTime
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )

                    LoggedTime = (
                        [datetime]$_.LoggedTime
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )

                    MinutesFromIncident = `
                        $_.MinutesFromIncident

                    IncidentPhase = `
                        $_.IncidentPhase

                    Position = `
                        $_.Position

                    Category = `
                        $_.Category

                    Level = `
                        $_.Level

                    SeverityScore = `
                        $_.SeverityScore

                    EventID = `
                        $_.EventID

                    Provider = `
                        $_.Provider

                    LifecycleContext = `
                        $_.LifecycleContext

                    EventSignature = `
                        $_.EventSignature

                    OccurrencesInCollection = `
                        $_.OccurrencesInCollection

                    OccurrencesInIncidentWindow = `
                        $_.OccurrencesInIncidentWindow

                    AnchorType = `
                        $_.AnchorType

                    Message = `
                        $_.Message
                }
            }


        [PSCustomObject]@{

            IncidentType = `
                $Incident.IncidentType

            AnchorTime = (
                [datetime]$Incident.AnchorTime
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )

            WindowStart = (
                [datetime]$Incident.WindowStart
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )

            WindowEnd = (
                [datetime]$Incident.WindowEnd
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )

            EventCount = `
                $Incident.EventCount

            Events = @(
                $ExportEvents
            )
        }
    }


Write-HalonJsonArray `
    -InputObject $IncidentExport `
    -Path (Join-Path $RunDirectory "incidents.json") `
    -Depth 10

# ---------------------------------------------
# EVENT PATTERN SUMMARY
# ---------------------------------------------

Write-Host "Grouping recurring events..."

$EventSummary = $Events |
    Group-Object Provider, EventID, Level |
    Sort-Object Count -Descending |
    ForEach-Object {

        [PSCustomObject]@{

            Count    = $_.Count
            Provider = $_.Group[0].Provider
            EventID  = $_.Group[0].EventID
            Level    = $_.Group[0].Level
        }
    }


Write-HalonJsonArray `
    -InputObject $EventSummary `
    -Path (Join-Path $RunDirectory "event-summary.json") `
    -Depth 4


# ---------------------------------------------
# RUN MANIFEST
# ---------------------------------------------

$Manifest = [PSCustomObject]@{

    Tool             = "HALON"
    Version          = "0.1"
    ComputerName     = $ComputerName
    CollectionStart  = $StartTime
    CollectionEnd    = Get-Date
    EventsCollected  = $Events.Count
    OutputDirectory  = $RunDirectory
    TimeZone = (Get-TimeZone).Id
    IdentityCollectionStatus = $IdentityCollectionStatus
    IdentityCollectionError  = $IdentityCollectionError
    WindowsSessionCollectionStatus = `
        $WindowsSessionCollectionStatus
    WindowsSessionCollectionError = `
        $WindowsSessionCollectionError
    ProcessCreationAuditPolicy = `
        $ProcessCreationAuditPolicy
    ProcessCreationAuditEnabled = `
        $ProcessCreationAuditEnabled
    ProcessCreationEvidenceStatus = `
        $ProcessCreationEvidenceStatus
    ProcessCreationEventsCollected = @(
        $ProcessCreationEvents
    ).Count
}


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