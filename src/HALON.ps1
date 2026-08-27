$ErrorActionPreference = "Stop"

# ---------------------------------------------
# LOAD HALON COMPONENTS
# ---------------------------------------------

. "$PSScriptRoot\core\Halon.Common.ps1"

. "$PSScriptRoot\collectors\Halon.HostCollector.ps1"
. "$PSScriptRoot\collectors\Halon.EventCollector.ps1"
. "$PSScriptRoot\collectors\Halon.IdentityCollector.ps1"

. "$PSScriptRoot\normalizers\Halon.EventNormalizer.ps1"
. "$PSScriptRoot\normalizers\Halon.IdentityNormalizer.ps1"

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
$SystemInfo = Get-HalonSystemInformation ` -ComputerName $ComputerName
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
$RawEvents = Get-HalonWindowsEventEvidence ` -StartTime $StartTime

# Normalize Windows events into HALON's internal structure.

$Events = ConvertTo-HalonEventEvidence ` -RawEvents $RawEvents

$Events |
    ConvertTo-Json -Depth 5 |
    Set-Content `
        (Join-Path $RunDirectory "events.json") `
        -Encoding UTF8

# ---------------------------------------------
# IDENTITY / SESSION EVIDENCE
# ---------------------------------------------

$IdentityCollection = Get-HalonIdentityEvidence ` -StartTime $StartTime

$IdentityEventsRaw = @($IdentityCollection.Events)

$IdentityCollectionStatus = ` $IdentityCollection.Status

$IdentityCollectionError = ` $IdentityCollection.Error

# ---------------------------------------------
# PROCESS CREATION EVIDENCE
# ---------------------------------------------

Write-Host "Checking historical process creation evidence..."

$ProcessCreationEventsRaw = @()

$ProcessCreationEvidenceStatus = "Available"
$ProcessCreationEvidenceError  = $null


try {

    $ProcessCreationEventsRaw = @(
        Get-WinEvent `
            -FilterHashtable @{
                LogName   = "Security"
                StartTime = $StartTime
                Id        = 4688
            } `
            -ErrorAction Stop
    )


    if ($ProcessCreationEventsRaw.Count -eq 0) {

        $ProcessCreationEvidenceStatus = `
            "NoEventsAvailable"
    }
}
catch {

    $ErrorMessage = $_.Exception.Message


    if (
        $ErrorMessage -like
        "*No events were found that match the specified selection criteria*"
    ) {

        $ProcessCreationEvidenceStatus = `
            "NoEventsAvailable"

        $ProcessCreationEvidenceError = $null
    }
    elseif (
        $_.Exception -is
        [System.UnauthorizedAccessException]
    ) {

        $ProcessCreationEvidenceStatus = `
            "UnavailableInsufficientPrivilege"

        $ProcessCreationEvidenceError = `
            $ErrorMessage
    }
    else {

        $ProcessCreationEvidenceStatus = `
            "Unavailable"

        $ProcessCreationEvidenceError = `
            $ErrorMessage
    }
}

# ---------------------------------------------
# NORMALIZE PROCESS CREATION EVIDENCE
# ---------------------------------------------

Write-Host "Normalizing historical process creation evidence..."

$ProcessCreationEvents = $ProcessCreationEventsRaw |
    Sort-Object TimeCreated |
    ForEach-Object {

        $EventData = Get-HalonEventData -Event $_


        # -------------------------------------
        # SUBJECT / CREATOR IDENTITY
        # -------------------------------------

        $SubjectUserSid = `
            $EventData["SubjectUserSid"]

        $SubjectUserName = `
            $EventData["SubjectUserName"]

        $SubjectDomainName = `
            $EventData["SubjectDomainName"]

        $SubjectLogonId = `
            $EventData["SubjectLogonId"]


        if (
            -not [string]::IsNullOrWhiteSpace(
                $SubjectDomainName
            ) -and

            -not [string]::IsNullOrWhiteSpace(
                $SubjectUserName
            )
        ) {

            $SubjectIdentity = `
                "$SubjectDomainName\$SubjectUserName"

        }
        else {

            $SubjectIdentity = $SubjectUserName
        }


        # -------------------------------------
        # NEW PROCESS
        # -------------------------------------

        $ProcessIdRaw = `
            $EventData["NewProcessId"]

        $ProcessIdDecimal = `
            Convert-HalonHexToInt64 `
                -Value $ProcessIdRaw

        $ProcessName = `
            $EventData["NewProcessName"]


        # -------------------------------------
        # CREATOR / PARENT PROCESS
        # -------------------------------------

        $ParentProcessIdRaw = `
            $EventData["ProcessId"]

        $ParentProcessIdDecimal = `
            Convert-HalonHexToInt64 `
                -Value $ParentProcessIdRaw

        $ParentProcessName = `
            $EventData["ParentProcessName"]


        # -------------------------------------
        # TARGET IDENTITY
        # -------------------------------------

        $TargetUserSid = `
            $EventData["TargetUserSid"]

        $TargetUserName = `
            $EventData["TargetUserName"]

        $TargetDomainName = `
            $EventData["TargetDomainName"]

        $TargetLogonId = `
            $EventData["TargetLogonId"]


        if (
            -not [string]::IsNullOrWhiteSpace(
                $TargetDomainName
            ) -and

            $TargetDomainName -ne "-" -and

            -not [string]::IsNullOrWhiteSpace(
                $TargetUserName
            ) -and

            $TargetUserName -ne "-"
        ) {

            $TargetIdentity = `
                "$TargetDomainName\$TargetUserName"

        }
        else {

            $TargetIdentity = $null
        }


        # -------------------------------------
        # NORMALIZED PROCESS EVENT
        # -------------------------------------

        [PSCustomObject]@{

            TimeCreated = $_.TimeCreated

            SecurityRecordId = $_.RecordId

            EventID = $_.Id


            SubjectIdentity   = $SubjectIdentity
            SubjectUserSid    = $SubjectUserSid
            SubjectUserName   = $SubjectUserName
            SubjectDomainName = $SubjectDomainName
            SubjectLogonId    = $SubjectLogonId


            ProcessIdRaw     = $ProcessIdRaw
            ProcessIdDecimal = $ProcessIdDecimal
            ProcessName      = $ProcessName


            ParentProcessIdRaw = `
                $ParentProcessIdRaw

            ParentProcessIdDecimal = `
                $ParentProcessIdDecimal

            ParentProcessName = `
                $ParentProcessName


            TargetIdentity   = $TargetIdentity
            TargetUserSid    = $TargetUserSid
            TargetUserName   = $TargetUserName
            TargetDomainName = $TargetDomainName
            TargetLogonId    = $TargetLogonId


            CommandLine = `
                $EventData["CommandLine"]

            TokenElevationType = `
                $EventData["TokenElevationType"]

            MandatoryLabel = `
                $EventData["MandatoryLabel"]
        }
    }

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
        $ProcessCreationEventsRaw
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

$IdentityEvents = ConvertTo-HalonIdentityEvidence ` -RawEvents $IdentityEventsRaw

# ---------------------------------------------
# RECONSTRUCT INTERACTIVE USER SESSIONS
# ---------------------------------------------

Write-Host "Reconstructing identity sessions..."

$IdentitySessions = @()


$InteractiveLogons = $IdentityEvents |
    Where-Object {

        $_.Action -eq "Logon" -and
        (Test-HalonInteractiveLogonType -LogonType $_.LogonType)

    } |
    Sort-Object TimeCreated


foreach ($Logon in $InteractiveLogons) {

    $LogonTime = [datetime]$Logon.TimeCreated
    $LogonId   = $Logon.LogonId


    # Look for the first matching end-of-session event
    # that occurs after this logon.

    $SessionEndEvent = $IdentityEvents |
        Where-Object {

            $_.LogonId -eq $LogonId -and

            [datetime]$_.TimeCreated -gt $LogonTime -and

            $_.Action -in @(
                "Logoff",
                "UserInitiatedLogoff"
            )

        } |
        Sort-Object TimeCreated |
        Select-Object -First 1


    if ($null -ne $SessionEndEvent) {

        $SessionEnd = [datetime]$SessionEndEvent.TimeCreated
        $SessionState = "Closed"
        $EndReason = $SessionEndEvent.Action

        $DurationMinutes = [math]::Round(
            ($SessionEnd - $LogonTime).TotalMinutes,
            2
        )

    }
    else {

        $SessionEnd = $null
        $SessionState = "OpenAtCollectionEnd"
        $EndReason = $null
        $DurationMinutes = $null
    }


    $IdentitySessions += [PSCustomObject]@{

        Identity = $Logon.Identity
        IdentityClass = $Logon.IdentityClass
        UserName = $Logon.UserName
        Domain   = $Logon.Domain
        UserSid  = $Logon.UserSid
        LogonId   = $Logon.LogonId
        LogonType = $Logon.LogonType

        SessionStart = $LogonTime
        SessionEnd   = $SessionEnd

        DurationMinutes = $DurationMinutes

        State     = $SessionState
        EndReason = $EndReason

        LogonRecordId = $Logon.RecordId

        LogoffRecordId = if ($null -ne $SessionEndEvent) {
            $SessionEndEvent.RecordId
        }
        else {
            $null
        }
    }
}

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

Write-Host "Collecting current Windows session snapshot..."

$CurrentSessions = @()

try {

    $QuserOutput = quser 2>$null

    if ($LASTEXITCODE -eq 0 -and $QuserOutput) {

        $SessionLines = $QuserOutput | Select-Object -Skip 1

        foreach ($Line in $SessionLines) {

            $CleanLine = $Line.TrimStart(">").Trim()

            $Parts = $CleanLine -split '\s{2,}'

            if ($Parts.Count -ge 4) {

                $UserName = $Parts[0]

                $SessionName = $null
                $SessionId   = $null
                $State       = $null
                $IdleTime    = $null
                $LogonTime   = $null

                if ($Parts.Count -ge 6) {

                    $SessionName = $Parts[1]
                    $SessionId   = $Parts[2]
                    $State       = $Parts[3]
                    $IdleTime    = $Parts[4]
                    $LogonTime   = $Parts[5]

                }
                elseif ($Parts.Count -eq 5) {

                    $SessionId = $Parts[1]
                    $State     = $Parts[2]
                    $IdleTime  = $Parts[3]
                    $LogonTime = $Parts[4]
                }

                $CurrentSessions += [PSCustomObject]@{
                    UserName    = $UserName
                    SessionName = $SessionName
                    SessionId   = $SessionId
                    State       = $State
                    IdleTime    = $IdleTime
                    LogonTime   = $LogonTime
                }
            }
        }
    }
}
catch {

    Write-Warning "HALON could not collect current Windows session snapshot."
}


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

Write-Host "Collecting Windows session lifecycle evidence..."

$WindowsSessionEventsRaw = @()

$WindowsSessionCollectionStatus = "Available"
$WindowsSessionCollectionError  = $null

$WindowsSessionLogName = `
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"


try {

    $WindowsSessionEventsRaw = Get-WinEvent `
        -FilterHashtable @{
            LogName   = $WindowsSessionLogName
            StartTime = $StartTime
            Id        = @(
                21,   # Session logon
                23,   # Session logoff
                24,   # Session disconnected
                25    # Session reconnected
            )
        } `
        -ErrorAction Stop

}
catch {

    $ErrorMessage = $_.Exception.Message

    if (
        $ErrorMessage -like
        "*No events were found that match the specified selection criteria*"
    ) {

        $WindowsSessionCollectionStatus = `
            "AvailableNoMatchingEvents"

        $WindowsSessionCollectionError = $null

        Write-Host `
            "No Windows session lifecycle events found in collection window."
    }
    else {

        $WindowsSessionCollectionStatus = "Unavailable"
        $WindowsSessionCollectionError  = $ErrorMessage

        Write-Warning `
            "HALON could not collect Windows session lifecycle evidence."
    }
}

# ---------------------------------------------
# NORMALIZE WINDOWS SESSION LIFECYCLE EVENTS
# ---------------------------------------------

$WindowsSessionEvents = $WindowsSessionEventsRaw |
    Sort-Object TimeCreated |
    ForEach-Object {

        $EventData = Get-HalonEventData -Event $_
        $UserData  = Get-HalonUserData -Event $_
        $SessionUser    = $UserData["User"]
        $SessionId      = $UserData["SessionID"]
        $SourceAddress  = $UserData["Address"]
        switch ($_.Id) {

            21 {
                $SessionAction = "SessionLogon"
            }

            23 {
                $SessionAction = "SessionLogoff"
            }

            24 {
                $SessionAction = "SessionDisconnect"
            }

            25 {
                $SessionAction = "SessionReconnect"
            }

            default {
                $SessionAction = "Unknown"
            }
        }


        [PSCustomObject]@{

            TimeCreated = $_.TimeCreated

            EventID = $_.Id

            Action = $SessionAction

            Provider = $_.ProviderName

            RecordId = $_.RecordId

            Message = $_.Message

            EventData = $EventData
            UserData  = $UserData
            User          = $SessionUser
            SessionId     = $SessionId
            SourceAddress = $SourceAddress 
        }
    }

# ---------------------------------------------
# WRITE WINDOWS SESSION LIFECYCLE EVIDENCE
# ---------------------------------------------

$WindowsSessionEvents |
    ConvertTo-Json -Depth 8 |
    Set-Content `
        (Join-Path $RunDirectory "windows-session-events.json") `
        -Encoding UTF8

# ---------------------------------------------
# RECONSTRUCT WINDOWS SESSIONS
# ---------------------------------------------

Write-Host "Reconstructing Windows sessions..."

$WindowsSessions = @()


$SessionLogons = $WindowsSessionEvents |
    Where-Object {
        $_.Action -eq "SessionLogon"
    } |
    Sort-Object TimeCreated


foreach ($Logon in $SessionLogons) {

    $SessionStart = [datetime]$Logon.TimeCreated
    $SessionId    = $Logon.SessionId
    $SessionUser  = $Logon.User


    # Find the first matching logoff occurring after
    # this session logon.

    $SessionLogoff = $WindowsSessionEvents |
        Where-Object {

            $_.Action -eq "SessionLogoff" -and

            $_.SessionId -eq $SessionId -and

            $_.User -eq $SessionUser -and

            [datetime]$_.TimeCreated -gt $SessionStart
        } |
        Sort-Object TimeCreated |
        Select-Object -First 1


    if ($null -ne $SessionLogoff) {

        $SessionEnd = [datetime]$SessionLogoff.TimeCreated
        $SessionState = "Closed"

    }
    else {

        $SessionEnd = $null
        $SessionState = "OpenAtCollectionEnd"
    }


    # Collect disconnect/reconnect activity belonging
    # to this session interval.

    $StateEvents = $WindowsSessionEvents |
        Where-Object {

            $_.SessionId -eq $SessionId -and

            $_.User -eq $SessionUser -and

            $_.Action -in @(
                "SessionDisconnect",
                "SessionReconnect"
            ) -and

            [datetime]$_.TimeCreated -ge $SessionStart -and

            (
                $null -eq $SessionEnd -or
                [datetime]$_.TimeCreated -le $SessionEnd
            )
        } |
        Sort-Object TimeCreated


    $WindowsSessions += [PSCustomObject]@{

        User = $SessionUser

        SessionId = $SessionId

        SourceAddress = $Logon.SourceAddress

        SessionStart = $SessionStart
        SessionEnd   = $SessionEnd

        State = $SessionState

        LogonRecordId = $Logon.RecordId

        LogoffRecordId = if ($null -ne $SessionLogoff) {
            $SessionLogoff.RecordId
        }
        else {
            $null
        }

        StateEvents = @(
            $StateEvents
        )
    }
}

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

Write-Host "Correlating processes with logon contexts..."

$ProcessLogonContexts = @()


foreach ($Process in $ProcessCreationEvents) {

    $MatchingLogon = $IdentityEvents |
        Where-Object {

            $_.Action -eq "Logon" -and
            $_.LogonId -eq $Process.SubjectLogonId -and
            [datetime]$_.TimeCreated -le [datetime]$Process.TimeCreated

        } |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 1


    if ($null -ne $MatchingLogon) {

        $LogonContextFound = $true

        $LogonIdentity = $MatchingLogon.Identity
        $LogonUserSid  = $MatchingLogon.UserSid
        $LogonType     = $MatchingLogon.LogonType
        $LogonTime     = $MatchingLogon.TimeCreated
        $LogonRecordId = $MatchingLogon.RecordId
    }
    else {

        $LogonContextFound = $false

        $LogonIdentity = $null
        $LogonUserSid  = $null
        $LogonType     = $null
        $LogonTime     = $null
        $LogonRecordId = $null
    }


    $ProcessLogonContexts += [PSCustomObject]@{

        ProcessTime = $Process.TimeCreated

        ProcessId = $Process.ProcessIdDecimal
        ProcessIdRaw = $Process.ProcessIdRaw
        ProcessName = $Process.ProcessName

        ParentProcessId = $Process.ParentProcessIdDecimal
        ParentProcessName = $Process.ParentProcessName

        SubjectIdentity = $Process.SubjectIdentity
        SubjectUserSid = $Process.SubjectUserSid
        SubjectLogonId = $Process.SubjectLogonId

        LogonContextFound = $LogonContextFound

        LogonIdentity = $LogonIdentity
        LogonUserSid = $LogonUserSid
        LogonType = $LogonType
        LogonTime = $LogonTime

        ProcessSecurityRecordId = $Process.SecurityRecordId
        LogonSecurityRecordId = $LogonRecordId

        EvidenceBasis = if ($LogonContextFound) {
            "SecurityLogonIdMatch"
        }
        else {
            "NoMatchingSecurityLogon"
        }
    }
}

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

Write-Host "Extracting event process references..."

$EventProcessReferences = @()


foreach ($Event in $Events) {

    $ProcessReference = Get-HalonEventProcessReference `
        -Event $Event


    if ($ProcessReference.HasProcessReference) {

        $EventProcessReferences += [PSCustomObject]@{

            EventTime = $Event.OccurrenceTime

            EventRecordId = $Event.RecordId

            EventProvider = $Event.Provider
            EventID       = $Event.EventID
            EventLevel    = $Event.Level

            ReferenceType = `
                $ProcessReference.ReferenceType

            ReferencedProcessIdRaw = `
                $ProcessReference.ProcessIdRaw

            ReferencedProcessId = `
                $ProcessReference.ProcessIdDecimal

            ReferencedProcessName = `
                $ProcessReference.ProcessName

            ReferencedProcessPath = `
                $ProcessReference.ProcessPath

            EventMessage = $Event.Message
        }
    }
}

# ---------------------------------------------
# EVENT / HISTORICAL PROCESS CORRELATION
# ---------------------------------------------

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
# CHRONOLOGICAL TIMELINE
# ---------------------------------------------

Write-Host "Building chronological timeline..."

$Timeline = $Events |
    Sort-Object OccurrenceTime |
    ForEach-Object {

        $Event = $_
        $AnchorType = $null

        switch ($Event.EventID) {

            41 {
                if ($Event.Provider -like "*Kernel-Power*") {
                    $AnchorType = "UnexpectedRestart"
                }
            }

            1001 {
                if ($Event.Provider -like "*BugCheck*") {
                    $AnchorType = "BugCheck"
                }
            }

            1074 {
                if ($Event.Provider -like "*User32*") {
                    $AnchorType = "PlannedShutdownOrRestart"
                }
            }

            6005 {
                if ($Event.Provider -eq "EventLog") {
                    $AnchorType = "EventLogStarted"
                }
            }

            6006 {
                if ($Event.Provider -eq "EventLog") {
                    $AnchorType = "EventLogStopped"
                }
            }

            6008 {
                if ($Event.Provider -eq "EventLog") {
                    $AnchorType = "UnexpectedShutdownConfirmed"
                }
            }
        }

        [PSCustomObject]@{
            LoggedTime     = $Event.LoggedTime
            OccurrenceTime = $Event.OccurrenceTime
            LogName     = $Event.LogName
            RecordId    = $Event.RecordId
            Level       = $Event.Level
            EventID     = $Event.EventID
            Provider    = $Event.Provider
            AnchorType  = $AnchorType
            Message     = $Event.Message
            Category       = $Event.Category
            EventSignature = $Event.EventSignature
            SeverityScore  = $Event.SeverityScore
        }
    }

# ---------------------------------------------
# BOOT SESSION RECONSTRUCTION
# ---------------------------------------------

Write-Host "Reconstructing boot sessions..."

$BootSessionNumber = 0
$BootSessionActive = $false


$Timeline = $Timeline |
    ForEach-Object {

        $Event = $_


        # EventLog 6005 indicates that the Windows
        # Event Log service has started.
        #
        # HALON uses this as a practical boot-session
        # boundary.

        if (
            $Event.Provider -eq "EventLog" -and
            $Event.EventID -eq 6005
        ) {

            $BootSessionNumber++
            $BootSessionActive = $true
        }


        if ($BootSessionNumber -eq 0) {

            $BootSessionId = "PRE_COLLECTION_BOOT"

        }
        else {

            $BootSessionId = "BOOT_{0:D3}" -f $BootSessionNumber
        }


        $Event |
            Add-Member `
                -NotePropertyName BootSessionId `
                -NotePropertyValue $BootSessionId `
                -Force


        $Event |
            Add-Member `
                -NotePropertyName BootSessionActive `
                -NotePropertyValue $BootSessionActive `
                -Force


        # EventLog 6006 means the Event Log service
        # stopped normally.

        if (
            $Event.Provider -eq "EventLog" -and
            $Event.EventID -eq 6006
        ) {

            $BootSessionActive = $false
        }


        $Event
    }

# ---------------------------------------------
# EVENT-TO-EVENT CHRONOLOGY
# ---------------------------------------------

Write-Host "Calculating event chronology deltas..."

$PreviousEventTime = $null


$Timeline = $Timeline |
    ForEach-Object {

        $EventTime = [datetime]$_.OccurrenceTime


        if ($null -eq $PreviousEventTime) {

            $SecondsSincePreviousEvent = $null

        }
        else {

            $SecondsSincePreviousEvent = [math]::Round(
                ($EventTime - $PreviousEventTime).TotalSeconds,
                3
            )
        }


        $_ |
            Add-Member `
                -NotePropertyName SecondsSincePreviousEvent `
                -NotePropertyValue $SecondsSincePreviousEvent `
                -Force


        $PreviousEventTime = $EventTime

        $_
    }

# ---------------------------------------------
# COLLECTION RECURRENCE
# ---------------------------------------------

Write-Host "Calculating event recurrence..."

$CollectionOccurrenceCounts = @{}

$Timeline |
    Group-Object EventSignature |
    ForEach-Object {

        if (-not [string]::IsNullOrWhiteSpace($_.Name)) {

            $CollectionOccurrenceCounts[$_.Name] = $_.Count

        }
    }


$Timeline = $Timeline |
    ForEach-Object {

        $OccurrenceCount = 0

        if (
            -not [string]::IsNullOrWhiteSpace($_.EventSignature) -and
            $CollectionOccurrenceCounts.ContainsKey($_.EventSignature)
        ) {
            $OccurrenceCount =
                $CollectionOccurrenceCounts[$_.EventSignature]
        }

        $_ |
            Add-Member `
                -NotePropertyName OccurrencesInCollection `
                -NotePropertyValue $OccurrenceCount `
                -Force

        $_
    }
    
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
            BootSessionId = ` $_.BootSessionId
            BootSessionActive = ` $_.BootSessionActive
            SecondsSincePreviousEvent = ` $_.SecondsSincePreviousEvent
        }
    }

Write-HalonJsonArray `
    -InputObject $TimelineExport `
    -Path (Join-Path $RunDirectory "timeline.json") `
    -Depth 5

# ---------------------------------------------
# FULL INCIDENT CONTEXT
# ---------------------------------------------

Write-Host "Building full incident context..."

$IncidentContexts = @()


$ContextAnchors = $Timeline |
    Where-Object {
        $_.AnchorType -eq "UnexpectedShutdownConfirmed"
    }


foreach ($Anchor in $ContextAnchors) {

    $AnchorTime = [datetime]$Anchor.OccurrenceTime


    $ContextEvents = $Timeline |
        ForEach-Object {

            $EventTime = [datetime]$_.OccurrenceTime

            $MinutesFromIncident = [math]::Round(
                ($EventTime - $AnchorTime).TotalMinutes,
                3
            )


            if ($_.RecordId -eq $Anchor.RecordId) {

                $IncidentPhase = "INCIDENT"

            }
            elseif ($EventTime -lt $AnchorTime) {

                $IncidentPhase = "PRE_INCIDENT"

            }
            else {

                $IncidentPhase = "POST_INCIDENT"
            }


            $WithinFocusedWindow = (
                $MinutesFromIncident -ge -30 -and
                $MinutesFromIncident -le 10
            )


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
                    $MinutesFromIncident

                IncidentPhase = `
                    $IncidentPhase

                WithinFocusedWindow = `
                    $WithinFocusedWindow

                BootSessionId = `
                    $_.BootSessionId

                BootSessionActive = `
                    $_.BootSessionActive

                SecondsSincePreviousEvent = `
                    $_.SecondsSincePreviousEvent

                LogName = `
                    $_.LogName

                RecordId = `
                    $_.RecordId

                Provider = `
                    $_.Provider

                EventID = `
                    $_.EventID

                Level = `
                    $_.Level

                SeverityScore = `
                    $_.SeverityScore

                Category = `
                    $_.Category

                EventSignature = `
                    $_.EventSignature

                OccurrencesInCollection = `
                    $_.OccurrencesInCollection

                AnchorType = `
                    $_.AnchorType

                Message = `
                    $_.Message
            }
        }


    $IncidentContexts += [PSCustomObject]@{

        IncidentType = "UnexpectedShutdown"

        AnchorTime = $AnchorTime.ToString(
            "MM/dd/yyyy HH:mm:ss"
        )

        CollectionEventCount = @(
            $ContextEvents
        ).Count

        Events = @(
            $ContextEvents
        )
    }
}


Write-HalonJsonArray `
    -InputObject $IncidentContexts `
    -Path (Join-Path $RunDirectory "incident-context.json") `
    -Depth 10

# ---------------------------------------------
# INCIDENT IDENTITY CORRELATION
# ---------------------------------------------

Write-Host "Correlating identity sessions to incidents..."

$IncidentIdentityContexts = @()


foreach ($Anchor in $ContextAnchors) {

    $AnchorTime = [datetime]$Anchor.OccurrenceTime


    $SessionsAtIncident = $IdentitySessions |
        Where-Object {

            $SessionStart = [datetime]$_.SessionStart

            if ($null -ne $_.SessionEnd) {

                $SessionEnd = [datetime]$_.SessionEnd

            }
            else {

                $SessionEnd = $null
            }


            $SessionStart -le $AnchorTime -and
            (
                $null -eq $SessionEnd -or
                $SessionEnd -ge $AnchorTime
            )
        } |
        ForEach-Object {

            [PSCustomObject]@{

                Identity      = $_.Identity
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

                SessionEndKnown = (
                    $null -ne $_.SessionEnd
                )

                SessionStateAtCollection = $_.State

                LogonRecordId  = $_.LogonRecordId
                LogoffRecordId = $_.LogoffRecordId

                EvidenceBasis = "SecurityLogIntervalOverlap"
            }
        }


    $IncidentIdentityContexts += [PSCustomObject]@{

        IncidentType = "UnexpectedShutdown"

        IncidentTime = $AnchorTime.ToString(
            "MM/dd/yyyy HH:mm:ss"
        )

        IdentityCollectionStatus = `
            $IdentityCollectionStatus

        CollectionWindowStart = (
            [datetime]$StartTime
        ).ToString(
            "MM/dd/yyyy HH:mm:ss"
        )

        SessionCount = @(
            $SessionsAtIncident
        ).Count

        Sessions = @(
            $SessionsAtIncident
        )
    }
}


Write-HalonJsonArray `
    -InputObject $IncidentIdentityContexts `
    -Path (Join-Path $RunDirectory "incident-identities.json") `
    -Depth 8

# ---------------------------------------------
# WINDOWS SESSION / INCIDENT CORRELATION
# ---------------------------------------------

Write-Host "Correlating Windows sessions to incidents..."

$WindowsSessionIncidentContexts = @()


foreach ($Anchor in $ContextAnchors) {

    $AnchorTime = [datetime]$Anchor.OccurrenceTime


    # Determine whether HALON's current collection window
    # actually covers the incident occurrence time.

    if ($AnchorTime -lt $StartTime) {

        $SessionEvidenceCoverage = "IncidentBeforeCollectionWindow"

    }
    else {

        $SessionEvidenceCoverage = "Covered"
    }


    # Only perform interval correlation when the incident
    # itself is inside the collected session-history window.

    if ($SessionEvidenceCoverage -eq "Covered") {

        $SessionsAtIncident = @(
            $WindowsSessions |
                Where-Object {

                    $SessionStart = [datetime]$_.SessionStart


                    if ($null -ne $_.SessionEnd) {

                        $SessionEnd = [datetime]$_.SessionEnd

                    }
                    else {

                        $SessionEnd = $null
                    }


                    $SessionStart -le $AnchorTime -and
                    (
                        $null -eq $SessionEnd -or
                        $SessionEnd -ge $AnchorTime
                    )
                } |
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

                        SessionStateAtCollection = $_.State

                        LogonRecordId = $_.LogonRecordId
                        LogoffRecordId = $_.LogoffRecordId

                        EvidenceBasis = `
                            "LocalSessionManagerIntervalOverlap"
                    }
                }
        )

    }
    else {

        $SessionsAtIncident = @()
    }


    $WindowsSessionIncidentContexts += [PSCustomObject]@{

        IncidentType = "UnexpectedShutdown"

        IncidentTime = $AnchorTime.ToString(
            "MM/dd/yyyy HH:mm:ss"
        )

        CollectionWindowStart = (
            [datetime]$StartTime
        ).ToString(
            "MM/dd/yyyy HH:mm:ss"
        )

        SessionEvidenceCoverage = `
            $SessionEvidenceCoverage

        SessionCount = @(
            $SessionsAtIncident
        ).Count

        Sessions = @(
            $SessionsAtIncident
        )
    }
}


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

Write-Host "Building enriched incident windows..."

$IncidentWindows = @()


$IncidentAnchors = $Timeline |
    Where-Object {
        $_.AnchorType -eq "UnexpectedShutdownConfirmed"
    }


foreach ($Anchor in $IncidentAnchors) {

    $AnchorTime = [datetime]$Anchor.OccurrenceTime

    $WindowStart = $AnchorTime.AddMinutes(-30)
    $WindowEnd   = $AnchorTime.AddMinutes(10)


    # -----------------------------------------
    # Collect raw events inside incident window
    # -----------------------------------------

    $WindowEventsBase = @(
        $Timeline |
            Where-Object {

                $EventTime = [datetime]$_.OccurrenceTime

                $EventTime -ge $WindowStart -and
                $EventTime -le $WindowEnd
            }
    )


    # -----------------------------------------
    # Count recurrence inside incident window
    # -----------------------------------------

    $IncidentOccurrenceCounts = @{}


    $WindowEventsBase |
        Group-Object EventSignature |
        ForEach-Object {

            $IncidentOccurrenceCounts[
                $_.Name
            ] = $_.Count
        }


    # -----------------------------------------
    # Enrich incident events
    # -----------------------------------------

    $WindowEvents = $WindowEventsBase |
        ForEach-Object {

            $EventTime = [datetime]$_.OccurrenceTime

            $MinutesFromIncident = [math]::Round(
                ($EventTime - $AnchorTime).TotalMinutes,
                2
            )


            if ($_.RecordId -eq $Anchor.RecordId) {

                $IncidentPhase = "INCIDENT"
                $Position      = "ANCHOR"

            }
            elseif ($EventTime -lt $AnchorTime) {

                $IncidentPhase = "PRE_INCIDENT"
                $Position      = "BEFORE"

            }
            else {

                $IncidentPhase = "POST_INCIDENT"
                $Position      = "AFTER"
            }


            $LifecycleContext = Get-HalonLifecycleContext `
                -Event $_


            [PSCustomObject]@{

                OccurrenceTime = $_.OccurrenceTime
                LoggedTime     = $_.LoggedTime

                MinutesFromIncident = $MinutesFromIncident

                IncidentPhase = $IncidentPhase
                Position      = $Position

                Category      = $_.Category

                Level         = $_.Level
                SeverityScore = $_.SeverityScore

                EventID       = $_.EventID
                Provider      = $_.Provider

                LifecycleContext = $LifecycleContext

                EventSignature = $_.EventSignature

                OccurrencesInCollection = `
                    $_.OccurrencesInCollection

                OccurrencesInIncidentWindow = `
                    $IncidentOccurrenceCounts[
                        $_.EventSignature
                    ]

                AnchorType = $_.AnchorType
                Message    = $_.Message
                BootSessionId = ` $_.BootSessionId
                BootSessionActive = ` $_.BootSessionActive
                SecondsSincePreviousEvent = ` $_.SecondsSincePreviousEvent
            }
        }


    # -----------------------------------------
    # Create incident object
    # -----------------------------------------

    $IncidentWindows += [PSCustomObject]@{

        IncidentType = "UnexpectedShutdown"

        AnchorTime  = $AnchorTime
        WindowStart = $WindowStart
        WindowEnd   = $WindowEnd

        EventCount = @(
            $WindowEvents
        ).Count

        Events = @(
            $WindowEvents
        )
    }
}


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
    WindowsSessionCollectionStatus = `    $WindowsSessionCollectionStatus
    WindowsSessionCollectionError = `    $WindowsSessionCollectionError
    ProcessCreationAuditPolicy = `    $ProcessCreationAuditPolicy
    ProcessCreationAuditEnabled = `    $ProcessCreationAuditEnabled
    ProcessCreationEvidenceStatus = `    $ProcessCreationEvidenceStatus
    ProcessCreationEventsCollected = @(    $ProcessCreationEventsRaw).Count
}


$Manifest |
    ConvertTo-Json |
    Set-Content `
        (Join-Path $RunDirectory "manifest.json") `
        -Encoding UTF8


Write-Host ""
Write-Host "======================================="
Write-Host " HALON COLLECTION COMPLETE"
Write-Host "======================================="
Write-Host ""
Write-Host "Events collected: $($Events.Count)"
Write-Host "Evidence directory:"
Write-Host $RunDirectory
Write-Host ""