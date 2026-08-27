# ---------------------------------------------
# HALON IDENTITY EVIDENCE COLLECTOR
# ---------------------------------------------


function Get-HalonIdentityEvidence {

    param (
        [datetime]$StartTime
    )


    Write-Host "Collecting identity and session evidence..."


    $IdentityEventsRaw = @()

    $IdentityCollectionStatus = "Available"
    $IdentityCollectionError  = $null


    try {

        $IdentityEventsRaw = @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName   = "Security"
                    StartTime = $StartTime

                    Id = @(
                        4624,
                        4634,
                        4647,
                        4778,
                        4779
                    )
                } `
                -ErrorAction Stop
        )

    }
    catch {

        $IdentityCollectionStatus = "Unavailable"
        $IdentityCollectionError  = $_.Exception.Message

        Write-Warning `
            "HALON could not read Security log identity evidence."
    }


    return [PSCustomObject]@{

        Events = @(
            $IdentityEventsRaw
        )

        Status = `
            $IdentityCollectionStatus

        Error = `
            $IdentityCollectionError
    }
}