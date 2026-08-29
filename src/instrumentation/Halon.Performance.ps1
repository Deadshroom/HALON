# ---------------------------------------------
# HALON PERFORMANCE INSTRUMENTATION
# ---------------------------------------------


function New-HalonPerformanceMetricList {

    return [System.Collections.Generic.List[object]]::new()
}


function Start-HalonStageTimer {

    return [System.Diagnostics.Stopwatch]::StartNew()
}


function Complete-HalonStageTimer {

    param (
        [Parameter(Mandatory)]
        [string]$Stage,

        [Parameter(Mandatory)]
        [System.Diagnostics.Stopwatch]$Stopwatch,

        [Parameter(Mandatory)]
        $Metrics,

        [Nullable[int64]]$ItemCount = $null
    )


    $Stopwatch.Stop()


    $ElapsedMilliseconds = [math]::Round(
        $Stopwatch.Elapsed.TotalMilliseconds,
        3
    )

    $ElapsedSeconds = [math]::Round(
        $Stopwatch.Elapsed.TotalSeconds,
        3
    )


    $ItemsPerSecond = $null


    if (
        $null -ne $ItemCount -and
        $ElapsedSeconds -gt 0
    ) {

        $ItemsPerSecond = [math]::Round(
            $ItemCount / $ElapsedSeconds,
            2
        )
    }


    $Metrics.Add(
        [PSCustomObject]@{

            Stage = $Stage

            ElapsedMilliseconds = `
                $ElapsedMilliseconds

            ElapsedSeconds = `
                $ElapsedSeconds

            ItemCount = `
                $ItemCount

            ItemsPerSecond = `
                $ItemsPerSecond
        }
    )


    Write-Host (
        "PERF  {0,-34} {1,8:N3}s" -f `
            $Stage,
            $ElapsedSeconds
    )
}


function Write-HalonPerformanceReport {

    param (
        [Parameter(Mandatory)]
        $Metrics,

        [Parameter(Mandatory)]
        [System.Diagnostics.Stopwatch]$RunStopwatch,

        [Parameter(Mandatory)]
        [string]$Path
    )


    if ($RunStopwatch.IsRunning) {
        $RunStopwatch.Stop()
    }


    $Report = [PSCustomObject]@{

        TotalElapsedMilliseconds = [math]::Round(
            $RunStopwatch.Elapsed.TotalMilliseconds,
            3
        )

        TotalElapsedSeconds = [math]::Round(
            $RunStopwatch.Elapsed.TotalSeconds,
            3
        )

        StageCount = @(
            $Metrics
        ).Count

        Stages = @(
            $Metrics
        )
    }


    $Report |
        ConvertTo-Json -Depth 7 |
        Set-Content `
            -Path $Path `
            -Encoding UTF8


    Write-Host ""
    Write-Host "HALON PERFORMANCE SUMMARY"
    Write-Host "-------------------------"


    $Metrics |
        Sort-Object ElapsedMilliseconds -Descending |
        Format-Table `
            Stage,
            ElapsedSeconds,
            ItemCount,
            ItemsPerSecond `
            -AutoSize


    Write-Host (
        "Total HALON runtime: {0:N3} seconds" -f `
            $RunStopwatch.Elapsed.TotalSeconds
    )
}