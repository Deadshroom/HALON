# ---------------------------------------------
# HALON PROCESS EVIDENCE COLLECTOR
# ---------------------------------------------

function Get-HalonProcessAuditCapability {

    $CurrentAuditPolicy = "Unknown"
    $SuccessAuditingEnabled = $false
    $AuditPolicyDetectionError = $null


    try {

        $AuditPolicyRaw = auditpol `
            /get `
            /subcategory:"Process Creation" `
            /r


        if (
            $LASTEXITCODE -eq 0 -and
            $AuditPolicyRaw
        ) {

            try {

                $AuditPolicyData = `
                    $AuditPolicyRaw |
                    ConvertFrom-Csv |
                    Select-Object -First 1


                $InclusionSetting = `
                    $AuditPolicyData.'Inclusion Setting'


                if (
                    -not [string]::IsNullOrWhiteSpace(
                        $InclusionSetting
                    )
                ) {

                    $CurrentAuditPolicy = `
                        $InclusionSetting


                    if (
                        $InclusionSetting -match
                        "Success"
                    ) {

                        $SuccessAuditingEnabled = `
                            $true
                    }
                }
            }
            catch {

                $CurrentAuditPolicy = `
                    "Unknown"

                $AuditPolicyDetectionError = `
                    "HALON could not parse auditpol output."
            }
        }
    }
    catch {

        $CurrentAuditPolicy = `
            "Unknown"

        $AuditPolicyDetectionError = `
            $_.Exception.Message
    }


    return [PSCustomObject]@{

        AuditSubcategory = `
            "Process Creation"

        CurrentAuditPolicy = `
            $CurrentAuditPolicy

        SuccessAuditingEnabled = `
            $SuccessAuditingEnabled

        AuditPolicyDetectionError = `
            $AuditPolicyDetectionError
    }
}


function New-HalonProcessEvidenceCapability {

    param (
        $AuditCapability,

        $ProcessCollection,

        $ProcessCreationEvents
    )


    return [PSCustomObject]@{

        AuditSubcategory = `
            $AuditCapability.AuditSubcategory


        CurrentAuditPolicy = `
            $AuditCapability.CurrentAuditPolicy

        SuccessAuditingEnabled = `
            $AuditCapability.SuccessAuditingEnabled

        AuditPolicyDetectionError = `
            $AuditCapability.AuditPolicyDetectionError


        Historical4688Status = `
            $ProcessCollection.Status

        Historical4688EventsCollected = @(
            $ProcessCreationEvents
        ).Count

        Historical4688CollectionError = `
            $ProcessCollection.Error
    }
}

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