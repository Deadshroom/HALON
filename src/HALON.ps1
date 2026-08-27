$ErrorActionPreference = "Stop"

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


function Test-IsAdministrator {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-HalonIdentityClass {

    param (
        [string]$UserSid,
        [string]$Identity
    )

    if (-not [string]::IsNullOrWhiteSpace($UserSid)) {

        switch -Regex ($UserSid) {

            '^S-1-5-18$' {
                return "System"
            }

            '^S-1-5-19$' {
                return "LocalService"
            }

            '^S-1-5-20$' {
                return "NetworkService"
            }

            '^S-1-5-90-' {
                return "WindowsVirtualAccount"
            }

            '^S-1-5-96-' {
                return "WindowsVirtualAccount"
            }

            '^S-1-5-80-' {
                return "ServiceIdentity"
            }

            '^S-1-5-82-' {
                return "ServiceOrApplicationIdentity"
            }

            '^S-1-5-21-' {
                return "Account"
            }
        }
    }


    # Fallback when the event did not supply a SID.

    if ($Identity -like "Window Manager\*") {
        return "WindowsVirtualAccount"
    }

    if ($Identity -like "Font Driver Host\*") {
        return "WindowsVirtualAccount"
    }

    if ($Identity -like "NT AUTHORITY\*") {
        return "WindowsAuthorityPrincipal"
    }

    return "Unknown"
}
function Get-HalonOccurrenceTime {

    param (
        $Event
    )

    $OccurrenceTime = $Event.TimeCreated

    if (
        $Event.Id -eq 6008 -and
        $Event.ProviderName -eq "EventLog"
    ) {

        try {

            [xml]$Xml = $Event.ToXml()

            $DataNodes = $Xml.SelectNodes(
                "//*[local-name()='EventData']/*[local-name()='Data']"
            )

            if ($DataNodes.Count -ge 2) {

                $ShutdownTime = $DataNodes[0].InnerText
                $ShutdownDate = $DataNodes[1].InnerText

                $TimestampText = "$ShutdownDate $ShutdownTime"

                $TimestampText = $TimestampText `
                    -replace '[\u200E\u200F\u202A-\u202E\u2066-\u2069]', ''

                $TimestampText = $TimestampText.Trim()

                $OccurrenceTime = [datetime]::ParseExact(
                    $TimestampText,
                    "M/d/yyyy h:mm:ss tt",
                    [Globalization.CultureInfo]::InvariantCulture
                )
            }
        }
        catch {

            Write-Warning "HALON could not parse Event 6008 occurrence time."
            Write-Warning $_.Exception.Message

            $OccurrenceTime = $Event.TimeCreated
        }
    }

    return $OccurrenceTime
}
function Get-HalonEventCategory {

    param (
        $Event
    )

    $Provider = $Event.ProviderName
    $Id       = $Event.Id

    # Hardware / WHEA
    if ($Provider -eq "Microsoft-Windows-WHEA-Logger") {
        return "Hardware"
    }

    # Bugcheck / BSOD reporting
    if (
        $Provider -eq "Microsoft-Windows-WER-SystemErrorReporting" -and
        $Id -eq 1001
    ) {
        return "BugCheck"
    }

    # Application crashes / hangs / Windows Error Reporting
    if (
        $Provider -in @(
            "Application Error",
            "Application Hang",
            "Windows Error Reporting"
        )
    ) {
        return "ApplicationFailure"
    }

    # Storage / disk / filesystem
    if (
        $Provider -match "disk|storahci|stornvme|iaStor|Ntfs|volmgr"
    ) {
        return "Storage"
    }

    # Service failures
    if (
        $Provider -eq "Service Control Manager" -and
        $Id -in @(7000,7001,7009,7011,7023,7031,7034)
    ) {
        return "ServiceFailure"
    }

    # Windows lifecycle
    if (
        ($Provider -eq "EventLog" -and $Id -in @(6005,6006,6008)) -or
        ($Provider -like "*Kernel-Power*" -and $Id -eq 41) -or
        ($Provider -eq "User32" -and $Id -eq 1074)
    ) {
        return "Lifecycle"
    }

    return "General"
}

function Get-HalonSeverityScore {

    param (
        [string]$Level
    )

    switch ($Level) {

        "Critical" {
            return 3
        }

        "Error" {
            return 2
        }

        "Warning" {
            return 1
        }

        default {
            return 0
        }
    }
}


function Get-HalonEventSignature {

    param (
        $Event
    )

    $Message = [string]$Event.Message

    if ([string]::IsNullOrWhiteSpace($Message)) {

        $FirstLine = "<no-message>"

    }
    else {

        $FirstLine = (
            $Message -split "\r?\n"
        )[0].Trim()
    }

    return "$($Event.ProviderName)|$($Event.Id)|$FirstLine"
}

function Get-HalonLifecycleContext {

    param (
        $Event
    )

    switch ($Event.AnchorType) {

        "UnexpectedShutdownConfirmed" {
            return "UnexpectedShutdown"
        }

        "UnexpectedRestart" {
            return "RestartDetection"
        }

        "PlannedShutdownOrRestart" {
            return "PlannedShutdownOrRestart"
        }

        "EventLogStarted" {
            return "EventLogStart"
        }

        "EventLogStopped" {
            return "EventLogStop"
        }

        default {
            return "None"
        }
    }
}

function Resolve-HalonSid {

    param (
        $Sid
    )

    if ($null -eq $Sid) {
        return $null
    }

    try {

        return $Sid.Translate(
            [System.Security.Principal.NTAccount]
        ).Value

    }
    catch {

        return $Sid.Value
    }
}
function Get-HalonEventData {

    param (
        $Event
    )

    $Result = @{}

    try {

        [xml]$Xml = $Event.ToXml()

        $DataNodes = $Xml.SelectNodes(
            "//*[local-name()='EventData']/*[local-name()='Data']"
        )

        $Index = 0

        foreach ($Node in $DataNodes) {

            $Name = $Node.GetAttribute("Name")

            if ([string]::IsNullOrWhiteSpace($Name)) {
                $Name = "Data_$Index"
            }

            $Result[$Name] = $Node.InnerText

            $Index++
        }
    }
    catch {
        # Return whatever we managed to collect.
    }

    return $Result
}
function Test-HalonInteractiveLogonType {

    param (
        $LogonType
    )

    return $LogonType -in @(
        2,   # Interactive
        10,  # RemoteInteractive
        11   # CachedInteractive
    )
}

function Get-HalonUserData {

    param (
        $Event
    )

    $Result = @{}

    try {

        [xml]$Xml = $Event.ToXml()

        $UserDataNode = $Xml.SelectSingleNode(
            "//*[local-name()='UserData']"
        )

        if ($null -ne $UserDataNode) {

            $LeafNodes = $UserDataNode.SelectNodes(
                ".//*[not(*)]"
            )

            foreach ($Node in $LeafNodes) {

                $Name = $Node.LocalName

                if (
                    -not [string]::IsNullOrWhiteSpace($Name)
                ) {

                    $Result[$Name] = $Node.InnerText
                }
            }
        }
    }
    catch {
        # Return whatever was successfully collected.
    }

    return $Result
}

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

function Convert-HalonHexToInt64 {

    param (
        $Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    try {

        $Text = [string]$Value

        if ($Text -match '^0x[0-9A-Fa-f]+$') {

            return [Convert]::ToInt64(
                $Text.Substring(2),
                16
            )
        }

        return [int64]$Text
    }
    catch {

        return $null
    }
}

function Get-HalonEventProcessReference {

    param (
        $Event
    )

    $Result = [ordered]@{
        HasProcessReference = $false

        ProcessIdRaw        = $null
        ProcessIdDecimal    = $null

        ProcessName         = $null
        ProcessPath         = $null

        ReferenceType       = $null
    }


    $Data = $Event.StructuredEventData


    if ($null -eq $Data) {
        return [PSCustomObject]$Result
    }


    # -----------------------------------------
    # APPLICATION ERROR - EVENT 1000
    # -----------------------------------------

    if (
        $Event.Provider -eq "Application Error" -and
        $Event.EventID -eq 1000
    ) {

        $Result.ReferenceType = "ApplicationError1000"

        $ProcessIdRaw = $Data.ProcessId

        if (-not [string]::IsNullOrWhiteSpace($ProcessIdRaw)) {

            $Result.ProcessIdRaw = $ProcessIdRaw

            $Result.ProcessIdDecimal = `
                Convert-HalonHexToInt64 `
                    -Value $ProcessIdRaw
        }


        if (
            -not [string]::IsNullOrWhiteSpace(
                $Data.AppPath
            )
        ) {

            $Result.ProcessPath = $Data.AppPath

            $Result.ProcessName = `
                [System.IO.Path]::GetFileName(
                    $Data.AppPath
                )
        }
        elseif (
            -not [string]::IsNullOrWhiteSpace(
                $Data.AppName
            )
        ) {

            $Result.ProcessName = $Data.AppName
        }


        if (
            $null -ne $Result.ProcessIdDecimal -or
            -not [string]::IsNullOrWhiteSpace(
                $Result.ProcessName
            )
        ) {

            $Result.HasProcessReference = $true
        }
    }


    return [PSCustomObject]$Result
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
Write-Host "Collecting system information..."
# ---------------------------------------------
# SYSTEM INFORMATION
# ---------------------------------------------
$OS = Get-CimInstance Win32_OperatingSystem
$Computer = Get-CimInstance Win32_ComputerSystem
$CPU = Get-CimInstance Win32_Processor
$SystemInfo = [PSCustomObject]@{
    ComputerName = $ComputerName
    Manufacturer = $Computer.Manufacturer
    Model        = $Computer.Model
    OS           = $OS.Caption
    OSVersion    = $OS.Version
    OSBuild      = $OS.BuildNumber
    LastBootTime = $OS.LastBootUpTime
    CPU          = $CPU.Name
    RAMGB        = [math]::Round(
        $Computer.TotalPhysicalMemory / 1GB,
        2
    )
    Administrator = Test-IsAdministrator
}
$SystemInfo |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        (Join-Path $RunDirectory "system-info.json") `
        -Encoding UTF8
# ---------------------------------------------
# DISK INFORMATION
# ---------------------------------------------

Write-Host "Collecting disk information..."

$Disks = Get-CimInstance Win32_LogicalDisk |
    Select-Object `
        DeviceID,
        VolumeName,
        FileSystem,
        DriveType,
        @{
            Name = "SizeGB"
            Expression = {
                [math]::Round($_.Size / 1GB, 2)
            }
        },
        @{
            Name = "FreeGB"
            Expression = {
                [math]::Round($_.FreeSpace / 1GB, 2)
            }
        }

$Disks |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        (Join-Path $RunDirectory "disks.json") `
        -Encoding UTF8


# ---------------------------------------------
# SERVICES
# ---------------------------------------------

Write-Host "Collecting service information..."

$Services = Get-Service |
    Select-Object Name, DisplayName, Status, StartType

$Services |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        (Join-Path $RunDirectory "services.json") `
        -Encoding UTF8


# ---------------------------------------------
# WINDOWS EVENT LOGS
# ---------------------------------------------

Write-Host "Collecting Windows Event Logs..."

# Primary diagnostic events:
# Critical, Error, and Warning from the last 24 hours.

$DiagnosticFilter = @{
    LogName   = @(
        "System",
        "Application"
    )
    StartTime = $StartTime
    Level     = @(1,2,3)
}

$DiagnosticEvents = Get-WinEvent `
    -FilterHashtable $DiagnosticFilter `
    -ErrorAction SilentlyContinue


# Lifecycle events:
# These may be informational, so we collect them separately.

$LifecycleFilter = @{
    LogName   = "System"
    StartTime = $StartTime
    Id        = @(
        41,      # Kernel-Power unexpected restart
        1001,    # BugCheck
        1074,    # Planned shutdown/restart
        6005,    # Event Log service started
        6006,    # Event Log service stopped
        6008     # Unexpected shutdown
    )
}

$LifecycleEvents = Get-WinEvent `
    -FilterHashtable $LifecycleFilter `
    -ErrorAction SilentlyContinue

# ---------------------------------------------
# SUPPLEMENTAL INCIDENT EVIDENCE
# ---------------------------------------------

Write-Host "Collecting supplemental incident evidence..."

$SupplementalEvents = @()


# Application crashes, hangs, and WER reports.
# Some WER events may be Information level and would
# therefore be missed by our normal diagnostic filter.

$SupplementalEvents += Get-WinEvent `
    -FilterHashtable @{
        LogName   = "Application"
        StartTime = $StartTime
        Id        = @(1000,1001,1002)
    } `
    -ErrorAction SilentlyContinue


# Hardware events from Windows Hardware Error Architecture.

$SupplementalEvents += Get-WinEvent `
    -FilterHashtable @{
        LogName      = "System"
        StartTime    = $StartTime
        ProviderName = "Microsoft-Windows-WHEA-Logger"
    } `
    -ErrorAction SilentlyContinue


# Storage-related Event IDs.
# Provider classification later determines whether these
# are actually storage evidence.

$SupplementalEvents += Get-WinEvent `
    -FilterHashtable @{
        LogName   = "System"
        StartTime = $StartTime
        Id        = @(
            7,
            11,
            15,
            51,
            55,
            98,
            129,
            153,
            157
        )
    } `
    -ErrorAction SilentlyContinue


# System-level crash / bugcheck reporting.

$SupplementalEvents += Get-WinEvent `
    -FilterHashtable @{
        LogName   = "System"
        StartTime = $StartTime
        Id        = 1001
    } `
    -ErrorAction SilentlyContinue

# Combine both collections and remove duplicates.

$RawEvents = @(
    $DiagnosticEvents
    $LifecycleEvents
    $SupplementalEvents
) |
    Sort-Object LogName, RecordId -Unique


# Normalize Windows events into HALON's internal structure.

$Events = $RawEvents |
    ForEach-Object {

        $OccurrenceTime = Get-HalonOccurrenceTime -Event $_
        $Category = Get-HalonEventCategory -Event $_
        $SeverityScore = Get-HalonSeverityScore `
            -Level $_.LevelDisplayName
        $EventSignature = Get-HalonEventSignature `
            -Event $_
        $EventUserSid = $null
        $EventUser    = $null
        $StructuredEventData = Get-HalonEventData -Event $_
        if ($null -ne $_.UserId) {

            $EventUserSid = $_.UserId.Value
            $EventUser    = Resolve-HalonSid -Sid $_.UserId
            }
        [PSCustomObject]@{
            LoggedTime     = $_.TimeCreated
            OccurrenceTime = $OccurrenceTime
            Category = $Category
            LogName        = $_.LogName
            RecordId       = $_.RecordId
            Level          = $_.LevelDisplayName
            EventID        = $_.Id
            Provider       = $_.ProviderName
            MachineName    = $_.MachineName
            Message        = $_.Message
            EventSignature = $EventSignature
            SeverityScore  = $SeverityScore
            EventUserSid = $EventUserSid
            EventUser    = $EventUser
            StructuredEventData = $StructuredEventData
        }
    }


$Events |
    ConvertTo-Json -Depth 5 |
    Set-Content `
        (Join-Path $RunDirectory "events.json") `
        -Encoding UTF8

# ---------------------------------------------
# IDENTITY / SESSION EVIDENCE
# ---------------------------------------------

Write-Host "Collecting identity and session evidence..."

$IdentityEventsRaw = @()
$IdentityCollectionStatus = "Available"
$IdentityCollectionError = $null

try {

    $IdentityEventsRaw = Get-WinEvent `
        -FilterHashtable @{
            LogName   = "Security"
            StartTime = $StartTime
            Id        = @(
                4624,
                4634,
                4647,
                4778,
                4779
            )
        } `
        -ErrorAction Stop

}
catch {

    $IdentityCollectionStatus = "Unavailable"
    $IdentityCollectionError  = $_.Exception.Message

    Write-Warning `
        "HALON could not read Security log identity evidence."
}

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


$ProcessCreationEventExport |
    ConvertTo-Json -Depth 6 |
    Set-Content `
        (Join-Path $RunDirectory "process-events.json") `
        -Encoding UTF8



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

$IdentityEvents = $IdentityEventsRaw |
    Sort-Object TimeCreated |
    ForEach-Object {

        $EventData = Get-HalonEventData -Event $_

        $Action = "Unknown"
        $UserName = $null
        $Domain   = $null
        $LogonId  = $null
        $LogonType = $null
        $UserSid = $null
        $SessionName   = $null
        $ClientName    = $null
        $ClientAddress = $null

        switch ($_.Id) {

            4624 {

                $Action = "Logon"

                $UserName = $EventData["TargetUserName"]
                $Domain   = $EventData["TargetDomainName"]
                $LogonId  = $EventData["TargetLogonId"]
                $LogonType = $EventData["LogonType"]
                $UserSid = $EventData["TargetUserSid"]
            }

            4634 {

                $Action = "Logoff"

                $UserName = $EventData["TargetUserName"]
                $Domain   = $EventData["TargetDomainName"]
                $LogonId  = $EventData["TargetLogonId"]
                $LogonType = $EventData["LogonType"]
                $UserSid = $EventData["TargetUserSid"]
            }

            4647 {

                $Action = "UserInitiatedLogoff"

                $UserName = $EventData["SubjectUserName"]
                $Domain   = $EventData["SubjectDomainName"]
                $LogonId  = $EventData["SubjectLogonId"]
                $UserSid = $EventData["SubjectUserSid"]
            }

            4778 {

                $Action = "SessionReconnect"

                $UserName = $EventData["AccountName"]
                $Domain   = $EventData["AccountDomain"]
                $LogonId  = $EventData["LogonID"]

                $SessionName   = $EventData["SessionName"]
                $ClientName    = $EventData["ClientName"]
                $ClientAddress = $EventData["ClientAddress"]
            }

            4779 {

                $Action = "SessionDisconnect"

                $UserName = $EventData["AccountName"]
                $Domain   = $EventData["AccountDomain"]
                $LogonId  = $EventData["LogonID"]

                $SessionName   = $EventData["SessionName"]
                $ClientName    = $EventData["ClientName"]
                $ClientAddress = $EventData["ClientAddress"]
            }
        }

        if (
            -not [string]::IsNullOrWhiteSpace($Domain) -and
            -not [string]::IsNullOrWhiteSpace($UserName)
        ) {
            $Identity = "$Domain\$UserName"
        }
        else {
            $Identity = $UserName
        }

        $IdentityClass = Get-HalonIdentityClass `
            -UserSid $UserSid `
            -Identity $Identity

        [PSCustomObject]@{
            TimeCreated  = $_.TimeCreated
            EventID      = $_.Id
            Action       = $Action

            Identity     = $Identity
            IdentityClass = $IdentityClass
            UserName     = $UserName
            Domain       = $Domain
            UserSid      = $UserSid
            LogonId      = $LogonId
            LogonType    = $LogonType

            SessionName  = $SessionName
            ClientName   = $ClientName
            ClientAddress = $ClientAddress

            RecordId     = $_.RecordId
        }
    }

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


$IdentitySessionExport |
    ConvertTo-Json -Depth 6 |
    Set-Content `
        (Join-Path $RunDirectory "identity-sessions.json") `
        -Encoding UTF8
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

$CurrentSessions |
    ConvertTo-Json -Depth 5 |
    Set-Content `
        (Join-Path $RunDirectory "current-sessions.json") `
        -Encoding UTF8

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


$WindowsSessionExport |
    ConvertTo-Json -Depth 8 |
    Set-Content `
        (Join-Path $RunDirectory "windows-sessions.json") `
        -Encoding UTF8

# ---------------------------------------------
# WRITE IDENTITY EVIDENCE
# ---------------------------------------------

$IdentityEvents |
    ConvertTo-Json -Depth 6 |
    Set-Content `
        (Join-Path $RunDirectory "identity-events.json") `
        -Encoding UTF8

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


$ProcessLogonContextExport |
    ConvertTo-Json -Depth 6 |
    Set-Content `
        (Join-Path $RunDirectory "process-logon-contexts.json") `
        -Encoding UTF8

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

$EventProcessCorrelationPath = Join-Path `
    $RunDirectory `
    "event-process-correlations.json"


if (@($EventProcessCorrelationExport).Count -eq 0) {

    $EventProcessCorrelationJson = "[]"

}
else {

    $EventProcessCorrelationJson = `
        $EventProcessCorrelationExport |
        ConvertTo-Json -Depth 7
}


Set-Content `
    -Path $EventProcessCorrelationPath `
    -Value $EventProcessCorrelationJson `
    -Encoding UTF8


Write-Host `
    "Event/process correlation artifact created: $(Test-Path $EventProcessCorrelationPath)"


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


$EvidenceSummary |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        (Join-Path $RunDirectory "evidence-summary.json") `
        -Encoding UTF8

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

$TimelineExport |
    ConvertTo-Json -Depth 5 |
    Set-Content `
        (Join-Path $RunDirectory "timeline.json") `
        -Encoding UTF8

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


$IncidentContexts |
    ConvertTo-Json -Depth 10 |
    Set-Content `
        (Join-Path $RunDirectory "incident-context.json") `
        -Encoding UTF8

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


$IncidentIdentityContexts |
    ConvertTo-Json -Depth 8 |
    Set-Content `
        (Join-Path $RunDirectory "incident-identities.json") `
        -Encoding UTF8

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


$WindowsSessionIncidentContexts |
    ConvertTo-Json -Depth 8 |
    Set-Content `
        (Join-Path $RunDirectory "windows-sessions-at-incident.json") `
        -Encoding UTF8    

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


$IncidentExport |
    ConvertTo-Json -Depth 10 |
    Set-Content `
        (Join-Path $RunDirectory "incidents.json") `
        -Encoding UTF8
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


$EventSummary |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        (Join-Path $RunDirectory "event-summary.json") `
        -Encoding UTF8


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