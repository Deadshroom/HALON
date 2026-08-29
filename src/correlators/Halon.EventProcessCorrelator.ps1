# ---------------------------------------------
# HALON EVENT / PROCESS CORRELATOR
# ---------------------------------------------


function Get-HalonEventProcessReferences {

    param (
        $Events
    )


    Write-Host "Extracting event process references..."


    $References = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Event in $Events) {

        $ProcessReference = `
            Get-HalonEventProcessReference `
                -Event $Event


        if (-not $ProcessReference.HasProcessReference) {
            continue
        }


        $References.Add(
            [PSCustomObject]@{

                EventTime = `
                    $Event.OccurrenceTime

                EventRecordId = `
                    $Event.RecordId

                EventProvider = `
                    $Event.Provider

                EventID = `
                    $Event.EventID

                EventLevel = `
                    $Event.Level


                ReferenceType = `
                    $ProcessReference.ReferenceType


                ReferencedProcessIdRaw = `
                    $ProcessReference.ProcessIdRaw

                ReferencedProcessId = `
                    $ProcessReference.ProcessIdDecimal

                ReferencedProcessName = `
                    $ProcessReference.ProcessName

                ReferencedProcessPath = `
                    $ProcessReference.ProcessPath


                EventMessage = `
                    $Event.Message
            }
        )
    }


    return $References.ToArray()
}


function Get-HalonEventProcessCorrelations {

    param (
        $EventProcessReferences,

        $ProcessLogonContexts
    )


    Write-Host "Correlating events with historical processes..."


    $Correlations = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Reference in $EventProcessReferences) {

        $EventTime = `
            [datetime]$Reference.EventTime


        # -------------------------------------
        # PID + CHRONOLOGY
        # -------------------------------------

        $PossibleMatches = `
            $ProcessLogonContexts |
            Where-Object {

                [datetime]$_.ProcessTime -le $EventTime -and

                $_.ProcessId -eq `
                    $Reference.ReferencedProcessId
            }


        # -------------------------------------
        # PROCESS NAME AGREEMENT
        # -------------------------------------

        if (
            -not [string]::IsNullOrWhiteSpace(
                $Reference.ReferencedProcessName
            )
        ) {

            $PossibleMatches = `
                $PossibleMatches |
                Where-Object {

                    $HistoricalName = `
                        [System.IO.Path]::GetFileName(
                            $_.ProcessName
                        )


                    $HistoricalName -ieq `
                        $Reference.ReferencedProcessName
                }
        }


        # -------------------------------------
        # PID REUSE PROTECTION
        # -------------------------------------
        #
        # Choose the newest compatible process
        # creation occurring before the event.

        $MatchingProcess = `
            $PossibleMatches |
            Sort-Object ProcessTime -Descending |
            Select-Object -First 1


        if ($null -ne $MatchingProcess) {

            $ProcessMatchFound = $true


            $ProcessAgeSeconds = [math]::Round(
                (
                    $EventTime -
                    [datetime]$MatchingProcess.ProcessTime
                ).TotalSeconds,
                3
            )


            if (
                -not [string]::IsNullOrWhiteSpace(
                    $Reference.ReferencedProcessName
                )
            ) {

                $MatchBasis = `
                    "ProcessIdAndProcessName"
            }
            else {

                $MatchBasis = `
                    "ProcessIdOnly"
            }
        }
        else {

            $ProcessMatchFound = $false
            $ProcessAgeSeconds = $null

            $MatchBasis = `
                "NoHistoricalProcessMatch"
        }


        # -------------------------------------
        # CORRELATION RESULT
        # -------------------------------------

        $Correlations.Add(
            [PSCustomObject]@{

                # EVENT

                EventTime = `
                    $Reference.EventTime

                EventRecordId = `
                    $Reference.EventRecordId

                EventProvider = `
                    $Reference.EventProvider

                EventID = `
                    $Reference.EventID

                EventLevel = `
                    $Reference.EventLevel


                # REFERENCED PROCESS

                ReferencedProcessId = `
                    $Reference.ReferencedProcessId

                ReferencedProcessName = `
                    $Reference.ReferencedProcessName

                ReferencedProcessPath = `
                    $Reference.ReferencedProcessPath


                # CORRELATION

                HistoricalProcessFound = `
                    $ProcessMatchFound

                MatchBasis = `
                    $MatchBasis

                ProcessAgeAtEventSeconds = `
                    $ProcessAgeSeconds


                # HISTORICAL PROCESS

                HistoricalProcessCreated = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.ProcessTime
                }
                else {

                    $null
                }


                HistoricalProcessName = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.ProcessName
                }
                else {

                    $null
                }
                HistoricalProcessSecurityRecordId = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.ProcessSecurityRecordId
                }
                else {

                    $null
                }

                ParentProcessName = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.ParentProcessName
                }
                else {

                    $null
                }


                ParentProcessId = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.ParentProcessId
                }
                else {

                    $null
                }


                # IDENTITY

                SubjectIdentity = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.SubjectIdentity
                }
                else {

                    $null
                }


                SubjectUserSid = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.SubjectUserSid
                }
                else {

                    $null
                }


                SubjectLogonId = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.SubjectLogonId
                }
                else {

                    $null
                }


                LogonContextFound = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.LogonContextFound
                }
                else {

                    $false
                }


                LogonIdentity = if (
                    $ProcessMatchFound
                ) {

                    $MatchingProcess.LogonIdentity
                }
                else {

                    $null
                }


                EvidenceBasis = if (
                    $ProcessMatchFound
                ) {

                    "WindowsEventProcessReference+Security4688"
                }
                else {

                    "WindowsEventProcessReferenceOnly"
                }
            }
        )
    }


    return $Correlations.ToArray()
}