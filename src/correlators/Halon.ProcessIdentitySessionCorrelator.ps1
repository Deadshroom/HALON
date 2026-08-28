# ---------------------------------------------
# HALON PROCESS / IDENTITY / SESSION CORRELATOR
# ---------------------------------------------


function Get-HalonProcessExecutionContexts {

    param (
        $ProcessLineages,
        $ProcessLogonContexts,
        $WindowsSessions
    )


    Write-Host "Connecting process lineages to identity and Windows session evidence..."


    # -----------------------------------------
    # INDEX PROCESS -> SECURITY LOGON CONTEXT
    # -----------------------------------------

    $LogonContextByProcessRecordId = @{}


    foreach ($Context in @($ProcessLogonContexts)) {

        if (
            $null -eq
            $Context.ProcessSecurityRecordId
        ) {
            continue
        }


        $RecordKey = `
            [string]$Context.ProcessSecurityRecordId


        $LogonContextByProcessRecordId[$RecordKey] = `
            $Context
    }


    # -----------------------------------------
    # INDEX WINDOWS SESSIONS BY USER
    # -----------------------------------------

    $WindowsSessionsByUser = @{}


    foreach ($Session in @($WindowsSessions)) {

        if (
            [string]::IsNullOrWhiteSpace(
                [string]$Session.User
            )
        ) {
            continue
        }


        $UserKey = `
            ([string]$Session.User).
                Trim().
                ToLowerInvariant()


        if (
            -not $WindowsSessionsByUser.ContainsKey(
                $UserKey
            )
        ) {

            $WindowsSessionsByUser[$UserKey] = `
                [System.Collections.Generic.List[object]]::new()
        }


        $WindowsSessionsByUser[$UserKey].Add(
            $Session
        )
    }


    # -----------------------------------------
    # CACHE ENRICHED PROCESS NODES
    # -----------------------------------------

    $NodeContextCache = @{}


    $ExecutionContexts = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($ProcessLineage in @($ProcessLineages)) {

        $ContextLineage = `
            [System.Collections.Generic.List[object]]::new()


        foreach ($Node in @($ProcessLineage.Lineage)) {

            $RecordKey = `
                [string]$Node.SecurityRecordId
            
            $CacheKey = `
                "$RecordKey|$($Node.Depth)"

            if (
                -not [string]::IsNullOrWhiteSpace(
                 $RecordKey
            ) -and
            $NodeContextCache.ContainsKey(
                $CacheKey
            )
        ) {

            $ContextLineage.Add(
                $NodeContextCache[$CacheKey]
            )

            continue
        }

            # ---------------------------------
            # SECURITY LOGON CONTEXT
            # ---------------------------------

            $LogonContext = $null


            if (
                -not [string]::IsNullOrWhiteSpace(
                    $RecordKey
                ) -and

                $LogonContextByProcessRecordId.ContainsKey(
                    $RecordKey
                )
            ) {

                $LogonContext = `
                    $LogonContextByProcessRecordId[
                        $RecordKey
                    ]
            }


            # ---------------------------------
            # WINDOWS SESSION CORRELATION
            # ---------------------------------

            $WindowsSessionMatches = `
                [System.Collections.Generic.List[object]]::new()


            $SubjectIdentity = `
                [string]$Node.SubjectIdentity


            $ProcessTime = `
                [datetime]$Node.ProcessTime


            if (
                -not [string]::IsNullOrWhiteSpace(
                    $SubjectIdentity
                )
            ) {

                $UserKey = `
                    $SubjectIdentity.
                        Trim().
                        ToLowerInvariant()


                if (
                    $WindowsSessionsByUser.ContainsKey(
                        $UserKey
                    )
                ) {

                    foreach (
                        $Session in
                        $WindowsSessionsByUser[$UserKey]
                    ) {

                        if (
                            $null -eq
                            $Session.SessionStart
                        ) {
                            continue
                        }


                        $SessionStart = `
                            [datetime]$Session.SessionStart


                        $SessionEnd = if (
                            $null -ne
                            $Session.SessionEnd
                        ) {

                            [datetime]$Session.SessionEnd
                        }
                        else {

                            $null
                        }


                        if (
                            $ProcessTime -lt
                            $SessionStart
                        ) {
                            continue
                        }


                        if (
                            $null -ne
                            $SessionEnd -and

                            $ProcessTime -gt
                            $SessionEnd
                        ) {
                            continue
                        }


                        $SecondsFromSessionStartToProcess = `
                            [math]::Round(
                                (
                                    $ProcessTime -
                                    $SessionStart
                                ).TotalSeconds,
                                3
                            )


                        $SecondsFromSecurityLogonToSessionStart = `
                            $null


                        if (
                            $null -ne
                            $LogonContext -and

                            $null -ne
                            $LogonContext.LogonTime
                        ) {

                            $SecondsFromSecurityLogonToSessionStart = `
                                [math]::Round(
                                    (
                                        $SessionStart -
                                        [datetime]$LogonContext.LogonTime
                                    ).TotalSeconds,
                                    3
                                )
                        }


                        $WindowsSessionMatches.Add(
                            [PSCustomObject]@{

                                User = `
                                    $Session.User

                                SessionId = `
                                    $Session.SessionId

                                SourceAddress = `
                                    $Session.SourceAddress


                                SessionStart = `
                                    $Session.SessionStart

                                SessionEnd = `
                                    $Session.SessionEnd

                                State = `
                                    $Session.State


                                LogonRecordId = `
                                    $Session.LogonRecordId

                                LogoffRecordId = `
                                    $Session.LogoffRecordId


                                SecondsFromSessionStartToProcess = `
                                    $SecondsFromSessionStartToProcess


                                SecondsFromSecurityLogonToSessionStart = `
                                    $SecondsFromSecurityLogonToSessionStart
                            }
                        )
                    }
                }
            }


            # ---------------------------------
            # WINDOWS SESSION EVIDENCE BASIS
            # ---------------------------------

            $WindowsSessionMatchCount = `
                $WindowsSessionMatches.Count


            if (
                [string]::IsNullOrWhiteSpace(
                    $SubjectIdentity
                )
            ) {

                $WindowsSessionEvidenceBasis = `
                    "SubjectIdentityUnavailable"
            }
            elseif (
                $WindowsSessionMatchCount -eq 0
            ) {

                $WindowsSessionEvidenceBasis = `
                    "NoExactSubjectIdentitySessionWindowMatch"
            }
            elseif (
                $WindowsSessionMatchCount -eq 1
            ) {

                $WindowsSessionEvidenceBasis = `
                    "ExactSubjectIdentityAndSessionWindow"
            }
            else {

                $WindowsSessionEvidenceBasis = `
                    "MultipleExactSubjectIdentitySessionWindowMatches"
            }


            # ---------------------------------
            # ENRICHED PROCESS NODE
            # ---------------------------------

            $NodeContext = `
                [PSCustomObject]@{

                    Depth = `
                        $Node.Depth


                    ProcessTime = `
                        $Node.ProcessTime

                    ProcessId = `
                        $Node.ProcessId

                    ProcessName = `
                        $Node.ProcessName

                    SecurityRecordId = `
                        $Node.SecurityRecordId


                    SubjectIdentity = `
                        $Node.SubjectIdentity

                    SubjectUserSid = `
                        $Node.SubjectUserSid

                    SubjectLogonId = `
                        $Node.SubjectLogonId


                    SecurityLogonContextFound = if (
                        $null -ne $LogonContext
                    ) {

                        [bool]$LogonContext.LogonContextFound
                    }
                    else {

                        $false
                    }


                    SecurityLogonIdentity = if (
                        $null -ne $LogonContext
                    ) {

                        $LogonContext.LogonIdentity
                    }
                    else {

                        $null
                    }


                    SecurityLogonUserSid = if (
                        $null -ne $LogonContext
                    ) {

                        $LogonContext.LogonUserSid
                    }
                    else {

                        $null
                    }


                    SecurityLogonType = if (
                        $null -ne $LogonContext
                    ) {

                        $LogonContext.LogonType
                    }
                    else {

                        $null
                    }


                    SecurityLogonTime = if (
                        $null -ne $LogonContext
                    ) {

                        $LogonContext.LogonTime
                    }
                    else {

                        $null
                    }


                    SecurityLogonRecordId = if (
                        $null -ne $LogonContext
                    ) {

                        $LogonContext.LogonSecurityRecordId
                    }
                    else {

                        $null
                    }


                    SecurityLogonEvidenceBasis = if (
                        $null -ne $LogonContext
                    ) {

                        $LogonContext.EvidenceBasis
                    }
                    else {

                        "NoProcessLogonCorrelationRecord"
                    }


                    WindowsSessionMatchCount = `
                        $WindowsSessionMatchCount


                    WindowsSessionEvidenceBasis = `
                        $WindowsSessionEvidenceBasis


                    WindowsSessionMatches = `
                        $WindowsSessionMatches.ToArray()


                    ParentProcessFound = `
                        $Node.ParentProcessFound


                    EvidenceBasisToParent = `
                        $Node.EvidenceBasisToParent
                }


            if (
                -not [string]::IsNullOrWhiteSpace(
                    $RecordKey
                )
            ) {

               $NodeContextCache[$CacheKey] = `
                    $NodeContext
            }


            $ContextLineage.Add(
                $NodeContext
            )
        }


        $ExecutionContexts.Add(
            [PSCustomObject]@{

                ProcessTime = `
                    $ProcessLineage.ProcessTime

                ProcessId = `
                    $ProcessLineage.ProcessId

                ProcessName = `
                    $ProcessLineage.ProcessName

                ProcessSecurityRecordId = `
                    $ProcessLineage.ProcessSecurityRecordId


                LineageNodeCount = `
                    $ProcessLineage.LineageNodeCount

                AncestorCount = `
                    $ProcessLineage.AncestorCount

                TerminationReason = `
                    $ProcessLineage.TerminationReason


                ContextLineage = `
                    $ContextLineage.ToArray()
            }
        )
    }


    return $ExecutionContexts.ToArray()
}