# ---------------------------------------------
# HALON INCIDENT / IDENTITY CORRELATOR
# ---------------------------------------------


function Get-HalonIncidentIdentityContexts {

    param (
        $IncidentAnchors,

        $IdentitySessions,

        [string]$IdentityCollectionStatus,

        [datetime]$CollectionWindowStart
    )


    Write-Host "Correlating identity sessions to incidents..."


    $IncidentIdentityContexts = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Anchor in $IncidentAnchors) {

        $AnchorTime = `
            [datetime]$Anchor.OccurrenceTime


        $SessionsAtIncident = @(
            $IdentitySessions |
                Where-Object {

                    $SessionStart = `
                        [datetime]$_.SessionStart


                    if (
                        $null -ne
                        $_.SessionEnd
                    ) {

                        $SessionEnd = `
                            [datetime]$_.SessionEnd
                    }
                    else {

                        $SessionEnd = `
                            $null
                    }


                    $SessionStart -le $AnchorTime -and
                    (
                        $null -eq $SessionEnd -or
                        $SessionEnd -ge $AnchorTime
                    )
                } |
                ForEach-Object {

                    [PSCustomObject]@{

                        Identity = `
                            $_.Identity

                        IdentityClass = `
                            $_.IdentityClass

                        UserName = `
                            $_.UserName

                        Domain = `
                            $_.Domain

                        UserSid = `
                            $_.UserSid


                        LogonId = `
                            $_.LogonId

                        LogonType = `
                            $_.LogonType


                        SessionStart = (
                            [datetime]$_.SessionStart
                        ).ToString(
                            "MM/dd/yyyy HH:mm:ss"
                        )


                        SessionEnd = if (
                            $null -ne $_.SessionEnd
                        ) {

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


                        SessionStateAtCollection = `
                            $_.State


                        LogonRecordId = `
                            $_.LogonRecordId

                        LogoffRecordId = `
                            $_.LogoffRecordId


                        EvidenceBasis = `
                            "SecurityLogIntervalOverlap"
                    }
                }
        )


        $IncidentIdentityContexts.Add(
            [PSCustomObject]@{

                IncidentType = `
                    "UnexpectedShutdown"

                IncidentTime = `
                    $AnchorTime.ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                IdentityCollectionStatus = `
                    $IdentityCollectionStatus


                CollectionWindowStart = `
                    $CollectionWindowStart.ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                SessionCount = `
                    $SessionsAtIncident.Count

                Sessions = `
                    $SessionsAtIncident
            }
        )
    }


    return $IncidentIdentityContexts.ToArray()
}