# ---------------------------------------------
# HALON WINDOWS EVENT NORMALIZER
# ---------------------------------------------


function ConvertTo-HalonEventEvidence {

    param (
        $RawEvents
    )


    Write-Host "Normalizing Windows event evidence..."


    $Events = $RawEvents |
        ForEach-Object {

            $OccurrenceTime = Get-HalonOccurrenceTime `
                -Event $_

            $Category = Get-HalonEventCategory `
                -Event $_

            $SeverityScore = Get-HalonSeverityScore `
                -Level $_.LevelDisplayName

            $EventSignature = Get-HalonEventSignature `
                -Event $_

            $StructuredEventData = Get-HalonEventData `
                -Event $_


            $EventUserSid = $null
            $EventUser    = $null


            if ($null -ne $_.UserId) {

                $EventUserSid = $_.UserId.Value

                $EventUser = Resolve-HalonSid `
                    -Sid $_.UserId
            }


            [PSCustomObject]@{

                LoggedTime = `
                    $_.TimeCreated

                OccurrenceTime = `
                    $OccurrenceTime

                Category = `
                    $Category

                LogName = `
                    $_.LogName

                RecordId = `
                    $_.RecordId

                Level = `
                    $_.LevelDisplayName

                EventID = `
                    $_.Id

                Provider = `
                    $_.ProviderName

                MachineName = `
                    $_.MachineName

                Message = `
                    $_.Message

                EventSignature = `
                    $EventSignature

                SeverityScore = `
                    $SeverityScore

                EventUserSid = `
                    $EventUserSid

                EventUser = `
                    $EventUser

                StructuredEventData = `
                    $StructuredEventData
            }
        }


    return @(
        $Events
    )
}