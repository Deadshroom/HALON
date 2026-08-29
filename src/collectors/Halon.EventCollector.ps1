# ---------------------------------------------
# HALON WINDOWS EVENT COLLECTOR
# ---------------------------------------------


function Get-HalonWindowsEventEvidence {

    param (
        [datetime]$StartTime
    )


    Write-Host "Collecting Windows Event Logs..."


    # -----------------------------------------
    # PRIMARY DIAGNOSTIC EVENTS
    # -----------------------------------------
    #
    # Critical, Error, and Warning events from
    # the System and Application logs.

    $DiagnosticEvents = Get-WinEvent `
        -FilterHashtable @{
            LogName = @(
                "System",
                "Application"
            )

            StartTime = $StartTime

            Level = @(
                1,
                2,
                3
            )
        } `
        -ErrorAction SilentlyContinue


    # -----------------------------------------
    # WINDOWS LIFECYCLE EVENTS
    # -----------------------------------------
    #
    # These may be informational, so HALON
    # collects them separately from diagnostic
    # severity filtering.

    $LifecycleEvents = Get-WinEvent `
        -FilterHashtable @{
            LogName   = "System"
            StartTime = $StartTime

            Id = @(
                41,      # Kernel-Power unexpected restart
                1001,    # BugCheck
                1074,    # Planned shutdown/restart
                6005,    # Event Log service started
                6006,    # Event Log service stopped
                6008     # Unexpected shutdown
            )
        } `
        -ErrorAction SilentlyContinue


    # -----------------------------------------
    # SUPPLEMENTAL INCIDENT EVIDENCE
    # -----------------------------------------

    Write-Host "Collecting supplemental incident evidence..."

    $SupplementalEvents = @()


    # Application crashes, hangs, and
    # Windows Error Reporting.

    $SupplementalEvents += Get-WinEvent `
        -FilterHashtable @{
            LogName   = "Application"
            StartTime = $StartTime
            Id        = @(1000,1001,1002)
        } `
        -ErrorAction SilentlyContinue


    # Windows Hardware Error Architecture.

    $SupplementalEvents += Get-WinEvent `
        -FilterHashtable @{
            LogName      = "System"
            StartTime    = $StartTime
            ProviderName = "Microsoft-Windows-WHEA-Logger"
        } `
        -ErrorAction SilentlyContinue


    # Storage-related Event IDs.

    $SupplementalEvents += Get-WinEvent `
        -FilterHashtable @{
            LogName   = "System"
            StartTime = $StartTime

            Id = @(
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


    # -----------------------------------------
    # COMBINE AND DEDUPLICATE
    # -----------------------------------------

    $RawEvents = @(
        $DiagnosticEvents
        $LifecycleEvents
        $SupplementalEvents
    ) |
        Sort-Object LogName, RecordId -Unique


    return @(
        $RawEvents
    )
}