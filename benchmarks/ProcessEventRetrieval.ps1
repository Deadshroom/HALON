param (
    [int]$Hours = 24,
    [int]$Iterations = 5
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------
# HALON PROCESS EVENT RETRIEVAL BENCHMARK
# ---------------------------------------------
# Compares multiple ways of retrieving the same
# Security Event 4688 population from Windows.
#
# This script does NOT modify audit policy or HALON.
# It is an isolated acquisition benchmark.
# ---------------------------------------------

function Test-IsAdministrator {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = [Security.Principal.WindowsPrincipal]::new(
        $Identity
    )

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}


function Invoke-HalonBenchmarkMethod {

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

    $Count = 0
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

                $Count = $Events.Count
            }


            "FilterXPath" {

                $Events = @(
                    Get-WinEvent `
                        -LogName "Security" `
                        -FilterXPath $XPath `
                        -ErrorAction Stop
                )

                $Count = $Events.Count
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
                            $Count++
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


            "WevtutilXml" {

                $Output = @(
                    & wevtutil.exe qe Security `
                        "/q:$XPath" `
                        /f:xml `
                        /rd:false `
                        2>&1
                )


                if ($LASTEXITCODE -ne 0) {

                    throw (
                        "wevtutil exited with code {0}: {1}" -f `
                            $LASTEXITCODE,
                            ($Output -join [Environment]::NewLine)
                    )
                }


                # XML output contains one <Event ...> element
                # per matching Windows event.

                $Count = @(
                    $Output |
                        Select-String `
                            -Pattern '<Event(?:\s|>)'
                ).Count
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


    return [PSCustomObject]@{

        Method = $Method

        Count = $Count

        ElapsedSeconds = [math]::Round(
            $Stopwatch.Elapsed.TotalSeconds,
            3
        )

        EventsPerSecond = if (
            $Count -gt 0 -and
            $Stopwatch.Elapsed.TotalSeconds -gt 0
        ) {

            [math]::Round(
                $Count / $Stopwatch.Elapsed.TotalSeconds,
                2
            )
        }
        else {

            0
        }

        Error = $ErrorMessage
    }
}


# ---------------------------------------------
# VALIDATION
# ---------------------------------------------

if (-not (Test-IsAdministrator)) {

    throw "Run this benchmark from an elevated PowerShell session."
}


if ($Hours -lt 1) {
    throw "Hours must be at least 1."
}


if ($Iterations -lt 1) {
    throw "Iterations must be at least 1."
}


# ---------------------------------------------
# FIXED BENCHMARK WINDOW
# ---------------------------------------------
#
# Start and end are captured once so every method
# is asked for the same historical event population.

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
    "EventLogReader",
    "WevtutilXml"
)


Write-Host ""
Write-Host "=============================================="
Write-Host " HALON PROCESS EVENT RETRIEVAL BENCHMARK"
Write-Host "=============================================="
Write-Host ""
Write-Host "Log:          Security"
Write-Host "Event ID:     4688"
Write-Host "Window Start: $StartTime"
Write-Host "Window End:   $EndTime"
Write-Host "Iterations:   $Iterations"
Write-Host ""


# ---------------------------------------------
# BENCHMARK
# ---------------------------------------------

$Results = [System.Collections.Generic.List[object]]::new()


for ($Round = 1; $Round -le $Iterations; $Round++) {

    Write-Host "Round $Round of $Iterations"


    # Randomize execution order each round to reduce
    # systematic cache/order bias between methods.

    $RoundMethods = $Methods |
        Sort-Object {
            Get-Random
        }


    foreach ($Method in $RoundMethods) {

        Write-Host "  Testing $Method..."

        $Result = Invoke-HalonBenchmarkMethod `
            -Method $Method `
            -StartTime $StartTime `
            -EndTime $EndTime `
            -XPath $XPath


        $Results.Add(
            [PSCustomObject]@{

                Round = $Round

                Method = $Result.Method

                Count = $Result.Count

                ElapsedSeconds = $Result.ElapsedSeconds

                EventsPerSecond = $Result.EventsPerSecond

                Error = $Result.Error
            }
        )


        if ($null -ne $Result.Error) {

            Write-Host (
                "    ERROR: {0}" -f $Result.Error
            )
        }
        else {

            Write-Host (
                "    {0} events in {1:N3}s ({2:N2}/sec)" -f `
                    $Result.Count,
                    $Result.ElapsedSeconds,
                    $Result.EventsPerSecond
            )
        }
    }


    Write-Host ""
}


# ---------------------------------------------
# RESULT VALIDATION
# ---------------------------------------------

$SuccessfulResults = @(
    $Results |
        Where-Object {
            $null -eq $_.Error
        }
)


$ObservedCounts = @(
    $SuccessfulResults |
        Select-Object -ExpandProperty Count -Unique
)


$CountsMatch = (
    $ObservedCounts.Count -le 1
)


# ---------------------------------------------
# SUMMARY
# ---------------------------------------------

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

                $MedianSeconds = `
                    $Times[[int]($Times.Count / 2)]

            }
            else {

                $UpperIndex = `
                    [int]($Times.Count / 2)

                $LowerIndex = `
                    $UpperIndex - 1

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
Write-Host "=============================================="
Write-Host " BENCHMARK SUMMARY"
Write-Host "=============================================="
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

if ($CountsMatch) {

    Write-Host "Event-count validation: PASS"

    if ($ObservedCounts.Count -eq 1) {
        Write-Host "Matching event count:     $($ObservedCounts[0])"
    }
}
else {

    Write-Warning "Event-count validation: FAIL"

    Write-Warning (
        "Observed counts: {0}" -f `
            ($ObservedCounts -join ", ")
    )

    Write-Warning `
        "Do not compare timing results until the queries return the same event population."
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
        Select-Object `
            Round,
            Method,
            Error |
        Format-Table -Wrap -AutoSize
}


# ---------------------------------------------
# OPTIONAL CSV OUTPUT
# ---------------------------------------------

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
    "process-event-retrieval-results.csv"

$SummaryPath = Join-Path `
    $ResultsDirectory `
    "process-event-retrieval-summary.csv"
    
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
