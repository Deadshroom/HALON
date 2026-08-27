# ---------------------------------------------
# HALON PROCESS EVIDENCE COLLECTOR
# ---------------------------------------------


function Get-HalonProcessCreationEvidence {

    param (
        [datetime]$StartTime,
        [datetime]$EndTime = (Get-Date)
    )


    Write-Host "Checking historical process creation evidence..."


    $ProcessEvents = `
        [System.Collections.Generic.List[object]]::new()


    $CollectionStatus = "Available"
    $CollectionError  = $null


    # EventLogReader XPath requires UTC timestamps.

    $StartUtc = $StartTime.ToUniversalTime().ToString(
        "yyyy-MM-ddTHH:mm:ss.fffZ",
        [Globalization.CultureInfo]::InvariantCulture
    )


    $EndUtc = $EndTime.ToUniversalTime().ToString(
        "yyyy-MM-ddTHH:mm:ss.fffZ",
        [Globalization.CultureInfo]::InvariantCulture
    )


    $XPath = `
        "*[System[(EventID=4688) and TimeCreated[@SystemTime >= '$StartUtc' and @SystemTime <= '$EndUtc']]]"


    $Query = $null
    $Reader = $null


    try {

        $Query = `
            [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
                "Security",
                [System.Diagnostics.Eventing.Reader.PathType]::LogName,
                $XPath
            )


        # Read oldest -> newest to preserve normal
        # chronological collection semantics.

        $Query.ReverseDirection = $false


        $Reader = `
            [System.Diagnostics.Eventing.Reader.EventLogReader]::new(
                $Query
            )


        while ($true) {

            $EventRecord = `
                $Reader.ReadEvent()


            if ($null -eq $EventRecord) {
                break
            }


            # Do NOT dispose here.
            #
            # The Process Normalizer owns each EventRecord
            # until it has extracted the structured evidence.

            $ProcessEvents.Add(
                $EventRecord
            )
        }


        if ($ProcessEvents.Count -eq 0) {

            $CollectionStatus = `
                "NoEventsAvailable"
        }
    }
    catch {

        $ErrorMessage = `
            $_.Exception.Message


        if (
            $_.Exception -is
            [System.UnauthorizedAccessException]
        ) {

            $CollectionStatus = `
                "UnavailableInsufficientPrivilege"
        }
        else {

            $CollectionStatus = `
                "Unavailable"
        }


        $CollectionError = `
            $ErrorMessage


        # If acquisition failed partway through,
        # release anything already materialized.

        foreach ($EventRecord in $ProcessEvents) {

            if ($null -ne $EventRecord) {

                $EventRecord.Dispose()
            }
        }


        $ProcessEvents.Clear()
    }
    finally {

        if ($null -ne $Reader) {

            $Reader.Dispose()
        }
    }


    return [PSCustomObject]@{

        Events = `
            $ProcessEvents

        Status = `
            $CollectionStatus

        Error = `
            $CollectionError

        StartTime = `
            $StartTime

        EndTime = `
            $EndTime

        Query = `
            $XPath
    }
}