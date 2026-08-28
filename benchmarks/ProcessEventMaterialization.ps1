param (
    [int]$Hours = 24,
    [int]$Iterations = 3
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# HALON PROCESS EVENT MATERIALIZATION BENCHMARK
# ------------------------------------------------------------
# Compares the same Security Event 4688 population while forcing
# each method to perform HALON-like per-event work:
#   - access core metadata
#   - call ToXml()
#   - parse EventData
#   - extract HALON process/security fields
#   - build normalized PowerShell objects
# ------------------------------------------------------------

function Test-IsAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]::new($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Convert-HalonHexToInt64 {
    param ($Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    try {
        $Text = [string]$Value

        if ($Text -match '^0x[0-9A-Fa-f]+$') {
            return [Convert]::ToInt64($Text.Substring(2), 16)
        }

        return [int64]$Text
    }
    catch {
        return $null
    }
}

function ConvertTo-HalonBenchmarkProcessRecord {
    param (
        [Parameter(Mandatory)]
        $Event
    )

    $EventData = @{}

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

        $EventData[$Name] = $Node.InnerText
        $Index++
    }

    $SubjectUserName = $EventData["SubjectUserName"]
    $SubjectDomainName = $EventData["SubjectDomainName"]

    if (
        -not [string]::IsNullOrWhiteSpace($SubjectDomainName) -and
        -not [string]::IsNullOrWhiteSpace($SubjectUserName)
    ) {
        $SubjectIdentity = "$SubjectDomainName\$SubjectUserName"
    }
    else {
        $SubjectIdentity = $SubjectUserName
    }

    $TargetUserName = $EventData["TargetUserName"]
    $TargetDomainName = $EventData["TargetDomainName"]

    if (
        -not [string]::IsNullOrWhiteSpace($TargetDomainName) -and
        $TargetDomainName -ne "-" -and
        -not [string]::IsNullOrWhiteSpace($TargetUserName) -and
        $TargetUserName -ne "-"
    ) {
        $TargetIdentity = "$TargetDomainName\$TargetUserName"
    }
    else {
        $TargetIdentity = $null
    }

    $ProcessIdRaw = $EventData["NewProcessId"]
    $ParentProcessIdRaw = $EventData["ProcessId"]

    return [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        SecurityRecordId = $Event.RecordId
        EventID = $Event.Id

        SubjectIdentity = $SubjectIdentity
        SubjectUserSid = $EventData["SubjectUserSid"]
        SubjectLogonId = $EventData["SubjectLogonId"]

        ProcessIdRaw = $ProcessIdRaw
        ProcessIdDecimal = Convert-HalonHexToInt64 -Value $ProcessIdRaw
        ProcessName = $EventData["NewProcessName"]

        ParentProcessIdRaw = $ParentProcessIdRaw
        ParentProcessIdDecimal = Convert-HalonHexToInt64 -Value $ParentProcessIdRaw
        ParentProcessName = $EventData["ParentProcessName"]

        TargetIdentity = $TargetIdentity
        TargetUserSid = $EventData["TargetUserSid"]
        TargetLogonId = $EventData["TargetLogonId"]

        CommandLine = $EventData["CommandLine"]
        TokenElevationType = $EventData["TokenElevationType"]
        MandatoryLabel = $EventData["MandatoryLabel"]
    }
}

function Invoke-HalonMaterializationBenchmark {
    param (
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [datetime]$StartTime,

        [Parameter(Mandatory)]
        [datetime]$EndTime,

        [Parameter(Mandatory)]
        [string]$XPath
    )

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $Normalized = [System.Collections.Generic.List[object]]::new()
    $ErrorMessage = $null

    try {
        switch ($Method) {
            "FilterHashtable" {
                $Events = @(
                    Get-WinEvent `
                        -FilterHashtable @{
                            LogName   = "Security"
                            Id        = 4688
                            StartTime = $StartTime
                            EndTime   = $EndTime
                        } `
                        -ErrorAction Stop
                )

                foreach ($Event in $Events) {
                    $Normalized.Add(
                        (ConvertTo-HalonBenchmarkProcessRecord -Event $Event)
                    )
                }
            }

            "FilterXPath" {
                $Events = @(
                    Get-WinEvent `
                        -LogName "Security" `
                        -FilterXPath $XPath `
                        -ErrorAction Stop
                )

                foreach ($Event in $Events) {
                    $Normalized.Add(
                        (ConvertTo-HalonBenchmarkProcessRecord -Event $Event)
                    )
                }
            }

            "EventLogReader" {
                $Query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
                    "Security",
                    [System.Diagnostics.Eventing.Reader.PathType]::LogName,
                    $XPath
                )

                $Query.ReverseDirection = $false

                $Reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new(
                    $Query
                )

                try {
                    while ($true) {
                        $EventRecord = $Reader.ReadEvent()

                        if ($null -eq $EventRecord) {
                            break
                        }

                        try {
                            $Normalized.Add(
                                (ConvertTo-HalonBenchmarkProcessRecord -Event $EventRecord)
                            )
                        }
                        finally {
                            $EventRecord.Dispose()
                        }
                    }
                }
                finally {
                    $Reader.Dispose()
                }
            }

            default {
                throw "Unknown benchmark method: $Method"
            }
        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
    }
    finally {
        $Stopwatch.Stop()
    }

    $RecordIds = @(
        $Normalized |
            ForEach-Object {
                [int64]$_.SecurityRecordId
            }
    )

    $RecordIdSum = 0L
    foreach ($RecordId in $RecordIds) {
        $RecordIdSum += $RecordId
    }

    return [PSCustomObject]@{
        Method = $Method
        Count = $Normalized.Count
        RecordIdSum = $RecordIdSum

        MinimumRecordId = if ($RecordIds.Count -gt 0) {
            ($RecordIds | Measure-Object -Minimum).Minimum
        }
        else {
            $null
        }

        MaximumRecordId = if ($RecordIds.Count -gt 0) {
            ($RecordIds | Measure-Object -Maximum).Maximum
        }
        else {
            $null
        }

        ElapsedSeconds = [math]::Round(
            $Stopwatch.Elapsed.TotalSeconds,
            3
        )

        EventsPerSecond = if (
            $Normalized.Count -gt 0 -and
            $Stopwatch.Elapsed.TotalSeconds -gt 0
        ) {
            [math]::Round(
                $Normalized.Count / $Stopwatch.Elapsed.TotalSeconds,
                2
            )
        }
        else {
            0
        }

        Error = $ErrorMessage
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Run this benchmark from an elevated PowerShell session."
}

if ($Hours -lt 1) {
    throw "Hours must be at least 1."
}

if ($Iterations -lt 1) {
    throw "Iterations must be at least 1."
}

# Capture a fixed historical window so every method evaluates
# exactly the same event population.
$EndTime = Get-Date
$StartTime = $EndTime.AddHours(-$Hours)

$StartUtc = $StartTime.ToUniversalTime().ToString(
    "yyyy-MM-ddTHH:mm:ss.fffZ",
    [Globalization.CultureInfo]::InvariantCulture
)

$EndUtc = $EndTime.ToUniversalTime().ToString(
    "yyyy-MM-ddTHH:mm:ss.fffZ",
    [Globalization.CultureInfo]::InvariantCulture
)

$XPath = "*[System[(EventID=4688) and TimeCreated[@SystemTime >= '$StartUtc' and @SystemTime <= '$EndUtc']]]"

$Methods = @(
    "FilterHashtable",
    "FilterXPath",
    "EventLogReader"
)

Write-Host ""
Write-Host "======================================================"
Write-Host " HALON PROCESS EVENT MATERIALIZATION BENCHMARK"
Write-Host "======================================================"
Write-Host ""
Write-Host "Log:          Security"
Write-Host "Event ID:     4688"
Write-Host "Window Start: $StartTime"
Write-Host "Window End:   $EndTime"
Write-Host "Iterations:   $Iterations"
Write-Host ""
Write-Host "Every method parses ToXml() and builds the same"
Write-Host "HALON-like normalized process records."
Write-Host ""

$Results = [System.Collections.Generic.List[object]]::new()

for ($Round = 1; $Round -le $Iterations; $Round++) {
    Write-Host "Round $Round of $Iterations"

    $RoundMethods = $Methods |
        Sort-Object {
            Get-Random
        }

    foreach ($Method in $RoundMethods) {
        Write-Host "  Testing $Method..."

        $Result = Invoke-HalonMaterializationBenchmark `
            -Method $Method `
            -StartTime $StartTime `
            -EndTime $EndTime `
            -XPath $XPath

        $Results.Add(
            [PSCustomObject]@{
                Round = $Round
                Method = $Result.Method
                Count = $Result.Count
                RecordIdSum = $Result.RecordIdSum
                MinimumRecordId = $Result.MinimumRecordId
                MaximumRecordId = $Result.MaximumRecordId
                ElapsedSeconds = $Result.ElapsedSeconds
                EventsPerSecond = $Result.EventsPerSecond
                Error = $Result.Error
            }
        )

        if ($null -ne $Result.Error) {
            Write-Host ("    ERROR: {0}" -f $Result.Error)
        }
        else {
            Write-Host (
                "    {0} normalized records in {1:N3}s ({2:N2}/sec)" -f `
                    $Result.Count,
                    $Result.ElapsedSeconds,
                    $Result.EventsPerSecond
            )
        }
    }

    Write-Host ""
}

$SuccessfulResults = @(
    $Results |
        Where-Object {
            $null -eq $_.Error
        }
)

$DatasetSignatures = @(
    $SuccessfulResults |
        ForEach-Object {
            "{0}|{1}|{2}|{3}" -f `
                $_.Count,
                $_.RecordIdSum,
                $_.MinimumRecordId,
                $_.MaximumRecordId
        } |
        Select-Object -Unique
)

$DatasetsMatch = ($DatasetSignatures.Count -le 1)

$Summary = @(
    $Methods |
        ForEach-Object {
            $Method = $_

            $MethodResults = @(
                $SuccessfulResults |
                    Where-Object {
                        $_.Method -eq $Method
                    }
            )

            if ($MethodResults.Count -eq 0) {
                [PSCustomObject]@{
                    Method = $Method
                    Runs = 0
                    EventCount = $null
                    AverageSeconds = $null
                    MedianSeconds = $null
                    BestSeconds = $null
                    WorstSeconds = $null
                    AverageEventsPerSecond = $null
                }

                return
            }

            $Times = @(
                $MethodResults |
                    Select-Object -ExpandProperty ElapsedSeconds |
                    Sort-Object
            )

            if ($Times.Count % 2 -eq 1) {
                $MedianSeconds = $Times[[int]($Times.Count / 2)]
            }
            else {
                $UpperIndex = [int]($Times.Count / 2)
                $LowerIndex = $UpperIndex - 1

                $MedianSeconds = (
                    $Times[$LowerIndex] +
                    $Times[$UpperIndex]
                ) / 2
            }

            [PSCustomObject]@{
                Method = $Method
                Runs = $MethodResults.Count

                EventCount = (
                    $MethodResults |
                        Select-Object -First 1
                ).Count

                AverageSeconds = [math]::Round(
                    (
                        $MethodResults |
                            Measure-Object `
                                -Property ElapsedSeconds `
                                -Average
                    ).Average,
                    3
                )

                MedianSeconds = [math]::Round(
                    $MedianSeconds,
                    3
                )

                BestSeconds = [math]::Round(
                    (
                        $MethodResults |
                            Measure-Object `
                                -Property ElapsedSeconds `
                                -Minimum
                    ).Minimum,
                    3
                )

                WorstSeconds = [math]::Round(
                    (
                        $MethodResults |
                            Measure-Object `
                                -Property ElapsedSeconds `
                                -Maximum
                    ).Maximum,
                    3
                )

                AverageEventsPerSecond = [math]::Round(
                    (
                        $MethodResults |
                            Measure-Object `
                                -Property EventsPerSecond `
                                -Average
                    ).Average,
                    2
                )
            }
        }
)

Write-Host ""
Write-Host "======================================================"
Write-Host " MATERIALIZATION BENCHMARK SUMMARY"
Write-Host "======================================================"
Write-Host ""

$Summary |
    Sort-Object MedianSeconds |
    Format-Table `
        Method,
        Runs,
        EventCount,
        AverageSeconds,
        MedianSeconds,
        BestSeconds,
        WorstSeconds,
        AverageEventsPerSecond `
        -AutoSize

Write-Host ""

if ($DatasetsMatch) {
    Write-Host "Dataset validation: PASS"

    if ($SuccessfulResults.Count -gt 0) {
        $First = $SuccessfulResults |
            Select-Object -First 1

        Write-Host "Event count:        $($First.Count)"
        Write-Host "Minimum Record ID:  $($First.MinimumRecordId)"
        Write-Host "Maximum Record ID:  $($First.MaximumRecordId)"
        Write-Host "Record ID checksum: $($First.RecordIdSum)"
    }
}
else {
    Write-Warning "Dataset validation: FAIL"
    Write-Warning "The methods did not materialize the same Record ID population."
    Write-Warning "Do not use the timing comparison until this is resolved."
}

$FailedResults = @(
    $Results |
        Where-Object {
            $null -ne $_.Error
        }
)

if ($FailedResults.Count -gt 0) {
    Write-Host ""
    Write-Host "FAILED METHOD RUNS"

    $FailedResults |
        Select-Object Round, Method, Error |
        Format-Table -Wrap -AutoSize
}

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$ResultsDirectory = Join-Path `
    $ScriptDirectory `
    "results"

New-Item `
    -Path $ResultsDirectory `
    -ItemType Directory `
    -Force |
    Out-Null

$ResultPath = Join-Path `
    $ResultsDirectory `
    "process-event-materialization-results.csv"

$SummaryPath = Join-Path `
    $ResultsDirectory `
    "process-event-materialization-summary.csv"

$Results |
    Export-Csv `
        -Path $ResultPath `
        -NoTypeInformation `
        -Encoding UTF8

$Summary |
    Export-Csv `
        -Path $SummaryPath `
        -NoTypeInformation `
        -Encoding UTF8

Write-Host ""
Write-Host "Detailed results:"
Write-Host $ResultPath
Write-Host ""
Write-Host "Summary:"
Write-Host $SummaryPath
Write-Host ""
