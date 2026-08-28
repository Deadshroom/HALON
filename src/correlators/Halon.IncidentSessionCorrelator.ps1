# ---------------------------------------------
# HALON INCIDENT / WINDOWS SESSION CORRELATOR
# ---------------------------------------------


function Get-HalonIncidentWindowsSessionContexts {

    param (
        $IncidentAnchors,

        $WindowsSessions,

        [datetime]$CollectionWindowStart
    )


    Write-Host "Correlating Windows sessions to incidents..."


    $IncidentSessionContexts = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Anchor in $IncidentAnchors) {

        $AnchorTime = `
            [datetime]$Anchor.OccurrenceTime


        # -------------------------------------
        # EVIDENCE COVERAGE
        # -------------------------------------

        if (
            $AnchorTime -lt
            $CollectionWindowStart
        ) {

            $SessionEvidenceCoverage = `
                "IncidentBeforeCollectionWindow"
        }
        else {

            $SessionEvidenceCoverage = `
                "Covered"
        }


        # -------------------------------------
        # SESSION INTERVAL CORRELATION
        # -------------------------------------

        if (
            $SessionEvidenceCoverage -eq
            "Covered"
        ) {

            $SessionsAtIncident = @(
                $WindowsSessions |
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

                            User = `
                                $_.User

                            SessionId = `
                                $_.SessionId

                            SourceAddress = `
                                $_.SourceAddress


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


                            SessionStateAtCollection = `
                                $_.State


                            LogonRecordId = `
                                $_.LogonRecordId

                            LogoffRecordId = `
                                $_.LogoffRecordId


                            EvidenceBasis = `
                                "LocalSessionManagerIntervalOverlap"
                        }
                    }
            )
        }
        else {

            $SessionsAtIncident = @()
        }


        $IncidentSessionContexts.Add(
            [PSCustomObject]@{

                IncidentType = `
                    "UnexpectedShutdown"

                IncidentTime = `
                    $AnchorTime.ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                CollectionWindowStart = `
                    $CollectionWindowStart.ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                SessionEvidenceCoverage = `
                    $SessionEvidenceCoverage


                SessionCount = `
                    $SessionsAtIncident.Count

                Sessions = `
                    $SessionsAtIncident
            }
        )
    }


    return $IncidentSessionContexts.ToArray()
}