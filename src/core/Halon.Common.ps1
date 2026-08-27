# ---------------------------------------------
# HALON COMMON FUNCTIONS
# ---------------------------------------------


function Test-IsAdministrator {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
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

            Write-Warning `
                "HALON could not parse Event 6008 occurrence time."

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

    if ($Provider -eq "Microsoft-Windows-WHEA-Logger") {
        return "Hardware"
    }

    if (
        $Provider -eq "Microsoft-Windows-WER-SystemErrorReporting" -and
        $Id -eq 1001
    ) {
        return "BugCheck"
    }

    if (
        $Provider -in @(
            "Application Error",
            "Application Hang",
            "Windows Error Reporting"
        )
    ) {
        return "ApplicationFailure"
    }

    if (
        $Provider -match "disk|storahci|stornvme|iaStor|Ntfs|volmgr"
    ) {
        return "Storage"
    }

    if (
        $Provider -eq "Service Control Manager" -and
        $Id -in @(7000,7001,7009,7011,7023,7031,7034)
    ) {
        return "ServiceFailure"
    }

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
        # Return whatever HALON successfully collected.
    }

    return $Result
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
        # Return whatever HALON successfully collected.
    }

    return $Result
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