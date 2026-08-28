# ---------------------------------------------
# HALON PROCESS TREE RECONSTRUCTOR
# ---------------------------------------------


function Get-HalonProcessTree {

    param (
        $ProcessCreationEvents
    )


    Write-Host "Reconstructing process tree..."


    # -----------------------------------------
    # BUILD PID INDEX
    # -----------------------------------------

    $ProcessIndex = @{}


    foreach ($Process in $ProcessCreationEvents) {

        $ProcessId = `
            [string]$Process.ProcessIdDecimal


        if (
            [string]::IsNullOrWhiteSpace(
                $ProcessId
            )
        ) {
            continue
        }


        if (
            -not $ProcessIndex.ContainsKey(
                $ProcessId
            )
        ) {

            $ProcessIndex[$ProcessId] = `
                [System.Collections.Generic.List[object]]::new()
        }


        $ProcessIndex[$ProcessId].Add(
            $Process
        )
    }


    # -----------------------------------------
    # RECONSTRUCT DIRECT PARENT RELATIONSHIPS
    # -----------------------------------------

    $ProcessTree = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($ChildProcess in $ProcessCreationEvents) {

        $ParentProcess = $null


        $ParentProcessId = `
            [string]$ChildProcess.ParentProcessIdDecimal


        $ExpectedParentName = `
            [System.IO.Path]::GetFileName(
                $ChildProcess.ParentProcessName
            )


        if (
            -not [string]::IsNullOrWhiteSpace(
                $ParentProcessId
            ) -and

            $ProcessIndex.ContainsKey(
                $ParentProcessId
            )
        ) {

            $Candidates = `
                $ProcessIndex[$ParentProcessId]


            # Search newest -> oldest because PID reuse
            # is possible.

            for (
                $Index = $Candidates.Count - 1
                $Index -ge 0
                $Index--
            ) {

                $Candidate = `
                    $Candidates[$Index]


                if (
                    [datetime]$Candidate.TimeCreated -gt
                    [datetime]$ChildProcess.TimeCreated
                ) {
                    continue
                }


                if (
                    -not [string]::IsNullOrWhiteSpace(
                        $ExpectedParentName
                    )
                ) {

                    $CandidateName = `
                        [System.IO.Path]::GetFileName(
                            $Candidate.ProcessName
                        )


                    if (
                        $CandidateName -ine
                        $ExpectedParentName
                    ) {
                        continue
                    }
                }


                $ParentProcess = `
                    $Candidate

                break
            }
        }


        if ($null -ne $ParentProcess) {

            $ParentProcessFound = $true


            $ParentAgeAtChildCreationSeconds = `
                [math]::Round(
                    (
                        [datetime]$ChildProcess.TimeCreated -
                        [datetime]$ParentProcess.TimeCreated
                    ).TotalSeconds,
                    3
                )


            if (
                -not [string]::IsNullOrWhiteSpace(
                    $ExpectedParentName
                )
            ) {

                $EvidenceBasis = `
                    "ParentProcessIdAndName"
            }
            else {

                $EvidenceBasis = `
                    "ParentProcessId"
            }
        }
        else {

            $ParentProcessFound = $false

            $ParentAgeAtChildCreationSeconds = `
                $null

            $EvidenceBasis = `
                "NoHistoricalParentProcessMatch"
        }


        $ProcessTree.Add(
            [PSCustomObject]@{

                # CHILD

                ProcessTime = `
                    $ChildProcess.TimeCreated

                ProcessId = `
                    $ChildProcess.ProcessIdDecimal

                ProcessName = `
                    $ChildProcess.ProcessName

                ProcessSecurityRecordId = `
                    $ChildProcess.SecurityRecordId


                SubjectIdentity = `
                    $ChildProcess.SubjectIdentity

                SubjectUserSid = `
                    $ChildProcess.SubjectUserSid

                SubjectLogonId = `
                    $ChildProcess.SubjectLogonId


                # RECORDED PARENT REFERENCE

                RecordedParentProcessId = `
                    $ChildProcess.ParentProcessIdDecimal

                RecordedParentProcessName = `
                    $ChildProcess.ParentProcessName


                # HISTORICAL PARENT MATCH

                ParentProcessFound = `
                    $ParentProcessFound


                ParentProcessTime = if (
                    $ParentProcessFound
                ) {

                    $ParentProcess.TimeCreated
                }
                else {

                    $null
                }


                ParentProcessId = if (
                    $ParentProcessFound
                ) {

                    $ParentProcess.ProcessIdDecimal
                }
                else {

                    $null
                }


                ParentProcessName = if (
                    $ParentProcessFound
                ) {

                    $ParentProcess.ProcessName
                }
                else {

                    $null
                }


                ParentProcessSecurityRecordId = if (
                    $ParentProcessFound
                ) {

                    $ParentProcess.SecurityRecordId
                }
                else {

                    $null
                }


                ParentSubjectIdentity = if (
                    $ParentProcessFound
                ) {

                    $ParentProcess.SubjectIdentity
                }
                else {

                    $null
                }


                ParentAgeAtChildCreationSeconds = `
                    $ParentAgeAtChildCreationSeconds


                EvidenceBasis = `
                    $EvidenceBasis
            }
        )
    }


    return $ProcessTree.ToArray()
}

function Get-HalonProcessLineages {

    param (
        $ProcessTree,

        [int]$MaxDepth = 64
    )


    Write-Host "Reconstructing process lineages..."


    # -----------------------------------------
    # INDEX PROCESS RECORDS
    # -----------------------------------------
    #
    # Direct parent relationships have already
    # been established by Get-HalonProcessTree.
    #
    # Security Record ID gives us a stable way
    # to follow those relationships without
    # repeating PID correlation.

    $ProcessByRecordId = @{}


    foreach ($Process in $ProcessTree) {

        if (
            $null -eq
            $Process.ProcessSecurityRecordId
        ) {
            continue
        }


        $RecordKey = `
            [string]$Process.ProcessSecurityRecordId


        $ProcessByRecordId[$RecordKey] = `
            $Process
    }


    # -----------------------------------------
    # BUILD LINEAGE FOR EVERY PROCESS
    # -----------------------------------------

    $ProcessLineages = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Process in $ProcessTree) {

        $Lineage = `
            [System.Collections.Generic.List[object]]::new()


        $VisitedRecords = `
            [System.Collections.Generic.HashSet[string]]::new()


        $CurrentProcess = `
            $Process

        $Depth = 0

        $TerminationReason = `
            $null


        while ($null -ne $CurrentProcess) {

            $CurrentRecordKey = `
                [string]$CurrentProcess.ProcessSecurityRecordId


            # ---------------------------------
            # CYCLE PROTECTION
            # ---------------------------------

            if (
                -not $VisitedRecords.Add(
                    $CurrentRecordKey
                )
            ) {

                $TerminationReason = `
                    "CycleDetected"

                break
            }


            # ---------------------------------
            # LINEAGE NODE
            # ---------------------------------

            $Lineage.Add(
                [PSCustomObject]@{

                    Depth = `
                        $Depth


                    ProcessTime = `
                        $CurrentProcess.ProcessTime

                    ProcessId = `
                        $CurrentProcess.ProcessId

                    ProcessName = `
                        $CurrentProcess.ProcessName

                    SecurityRecordId = `
                        $CurrentProcess.ProcessSecurityRecordId


                    SubjectIdentity = `
                        $CurrentProcess.SubjectIdentity

                    SubjectUserSid = `
                        $CurrentProcess.SubjectUserSid

                    SubjectLogonId = `
                        $CurrentProcess.SubjectLogonId


                    ParentProcessFound = `
                        $CurrentProcess.ParentProcessFound

                    EvidenceBasisToParent = `
                        $CurrentProcess.EvidenceBasis
                }
            )


            # ---------------------------------
            # NO HISTORICAL PARENT
            # ---------------------------------

            if (
                -not
                $CurrentProcess.ParentProcessFound
            ) {

                $TerminationReason = `
                    "NoHistoricalParentProcessMatch"

                break
            }


            # ---------------------------------
            # DEPTH SAFEGUARD
            # ---------------------------------

            if ($Depth -ge $MaxDepth) {

                $TerminationReason = `
                    "MaxDepthReached"

                break
            }


            # ---------------------------------
            # FOLLOW ESTABLISHED PARENT EDGE
            # ---------------------------------

            $ParentRecordKey = `
                [string]$CurrentProcess.ParentProcessSecurityRecordId


            if (
                [string]::IsNullOrWhiteSpace(
                    $ParentRecordKey
                ) -or

                -not $ProcessByRecordId.ContainsKey(
                    $ParentRecordKey
                )
            ) {

                $TerminationReason = `
                    "ParentRecordNotAvailable"

                break
            }


            $CurrentProcess = `
                $ProcessByRecordId[
                    $ParentRecordKey
                ]


            $Depth++
        }


        # -------------------------------------
        # LINEAGE RESULT
        # -------------------------------------

        $ProcessLineages.Add(
            [PSCustomObject]@{

                ProcessTime = `
                    $Process.ProcessTime

                ProcessId = `
                    $Process.ProcessId

                ProcessName = `
                    $Process.ProcessName

                ProcessSecurityRecordId = `
                    $Process.ProcessSecurityRecordId


                LineageNodeCount = `
                    $Lineage.Count

                AncestorCount = `
                    [math]::Max(
                        0,
                        $Lineage.Count - 1
                    )


                TerminationReason = `
                    $TerminationReason


                Lineage = `
                    $Lineage.ToArray()
            }
        )
    }


    return $ProcessLineages.ToArray()
}