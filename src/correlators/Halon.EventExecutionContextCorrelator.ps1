# ---------------------------------------------
# HALON EVENT / EXECUTION CONTEXT CORRELATOR
# ---------------------------------------------


function Get-HalonEventExecutionContexts {

    param (
        $EventProcessCorrelations,

        $ProcessExecutionContexts
    )


    Write-Host "Connecting events to process execution contexts..."


    # -----------------------------------------
    # INDEX EXECUTION CONTEXTS BY 4688 RECORD
    # -----------------------------------------

    $ExecutionContextByProcessRecordId = @{}


    foreach (
        $ExecutionContextItem in
        @($ProcessExecutionContexts)
    ) {

        if (
            $null -eq
            $ExecutionContextItem.ProcessSecurityRecordId
        ) {
            continue
        }


        $RecordKey = `
            [string]$ExecutionContextItem.ProcessSecurityRecordId


        $ExecutionContextByProcessRecordId[$RecordKey] = `
            $ExecutionContextItem
    }


    # -----------------------------------------
    # CONNECT EVENT TO EXECUTION CONTEXT
    # -----------------------------------------

    $Results = `
        [System.Collections.Generic.List[object]]::new()


    foreach (
        $EventCorrelation in
        @($EventProcessCorrelations)
    ) {

        $ExecutionContextFound = $false
        $MatchedExecutionContext = $null


        if (
            $EventCorrelation.HistoricalProcessFound -and

            $null -ne
            $EventCorrelation.HistoricalProcessSecurityRecordId
        ) {

            $RecordKey = `
                [string]$EventCorrelation.HistoricalProcessSecurityRecordId


            if (
                $ExecutionContextByProcessRecordId.ContainsKey(
                    $RecordKey
                )
            ) {

                $ExecutionContextFound = $true

            $MatchedExecutionContext = `
                 $ExecutionContextByProcessRecordId[
                    $RecordKey
                ]
            }
        }


        $EvidenceBasis = if (
            -not $EventCorrelation.HistoricalProcessFound
        ) {

            "NoHistoricalProcessMatch"
        }
        elseif (
            $null -eq
            $EventCorrelation.HistoricalProcessSecurityRecordId
        ) {

            "HistoricalProcessRecordIdUnavailable"
        }
        elseif (
            $ExecutionContextFound
        ) {

            "HistoricalProcessSecurityRecordIdMatch"
        }
        else {

            "NoExecutionContextForHistoricalProcessRecord"
        }


        $Results.Add(
            [PSCustomObject]@{

                # EVENT

                EventTime = `
                    $EventCorrelation.EventTime

                EventRecordId = `
                    $EventCorrelation.EventRecordId

                EventProvider = `
                    $EventCorrelation.EventProvider

                EventID = `
                    $EventCorrelation.EventID

                EventLevel = `
                    $EventCorrelation.EventLevel


                # PROCESS REFERENCE

                ReferencedProcessId = `
                    $EventCorrelation.ReferencedProcessId

                ReferencedProcessName = `
                    $EventCorrelation.ReferencedProcessName

                ReferencedProcessPath = `
                    $EventCorrelation.ReferencedProcessPath


                # HISTORICAL PROCESS

                HistoricalProcessFound = `
                    $EventCorrelation.HistoricalProcessFound

                HistoricalProcessSecurityRecordId = `
                    $EventCorrelation.HistoricalProcessSecurityRecordId

                HistoricalProcessCreated = `
                    $EventCorrelation.HistoricalProcessCreated

                HistoricalProcessName = `
                    $EventCorrelation.HistoricalProcessName


                # EXECUTION CONTEXT

                ExecutionContextFound = `
                    $ExecutionContextFound

                EvidenceBasis = `
                    $EvidenceBasis


                ProcessExecutionContext = `
                    $MatchedExecutionContext
            }
        )
    }


    return $Results.ToArray()
}