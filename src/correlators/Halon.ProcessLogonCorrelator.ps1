# ---------------------------------------------
# HALON PROCESS / LOGON CORRELATOR
# ---------------------------------------------


function New-HalonLogonIndex {

    param (
        $IdentityEvents
    )


    $LogonIndex = @{}


    foreach ($Event in $IdentityEvents) {

        if (
            $Event.Action -ne "Logon" -or
            [string]::IsNullOrWhiteSpace($Event.LogonId)
        ) {
            continue
        }


        $LogonId = [string]$Event.LogonId


        if (-not $LogonIndex.ContainsKey($LogonId)) {

            $LogonIndex[$LogonId] = `
                [System.Collections.Generic.List[object]]::new()
        }


        $LogonIndex[$LogonId].Add($Event)
    }


    return ,$LogonIndex
}


function Get-HalonProcessLogonCorrelations {

    param (
        $ProcessCreationEvents,

        [hashtable]$LogonIndex
    )


    Write-Host "Correlating processes with logon contexts..."


    $ProcessLogonContexts = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Process in $ProcessCreationEvents) {

        $MatchingLogon = $null

        $SubjectLogonId = `
            [string]$Process.SubjectLogonId


        # -------------------------------------
        # DIRECT LOGON-ID LOOKUP
        # -------------------------------------

        if (
            -not [string]::IsNullOrWhiteSpace(
                $SubjectLogonId
            ) -and

            $LogonIndex.ContainsKey(
                $SubjectLogonId
            )
        ) {

            $CandidateLogons = `
                $LogonIndex[$SubjectLogonId]


            # Identity events were normalized in
            # chronological order.
            #
            # Search backward so the first valid
            # record is the most recent matching
            # logon occurring at or before process
            # creation.

            for (
                $Index = $CandidateLogons.Count - 1
                $Index -ge 0
                $Index--
            ) {

                $Candidate = `
                    $CandidateLogons[$Index]


                if (
                    [datetime]$Candidate.TimeCreated -le
                    [datetime]$Process.TimeCreated
                ) {

                    $MatchingLogon = `
                        $Candidate

                    break
                }
            }
        }


        # -------------------------------------
        # CORRELATION RESULT
        # -------------------------------------

        if ($null -ne $MatchingLogon) {

            $LogonContextFound = $true

            $LogonIdentity = `
                $MatchingLogon.Identity

            $LogonUserSid = `
                $MatchingLogon.UserSid

            $LogonType = `
                $MatchingLogon.LogonType

            $LogonTime = `
                $MatchingLogon.TimeCreated

            $LogonRecordId = `
                $MatchingLogon.RecordId
        }
        else {

            $LogonContextFound = $false

            $LogonIdentity = $null
            $LogonUserSid  = $null
            $LogonType     = $null
            $LogonTime     = $null
            $LogonRecordId = $null
        }


        $ProcessLogonContexts.Add(
            [PSCustomObject]@{

                ProcessTime = `
                    $Process.TimeCreated


                ProcessId = `
                    $Process.ProcessIdDecimal

                ProcessIdRaw = `
                    $Process.ProcessIdRaw

                ProcessName = `
                    $Process.ProcessName


                ParentProcessId = `
                    $Process.ParentProcessIdDecimal

                ParentProcessName = `
                    $Process.ParentProcessName


                SubjectIdentity = `
                    $Process.SubjectIdentity

                SubjectUserSid = `
                    $Process.SubjectUserSid

                SubjectLogonId = `
                    $Process.SubjectLogonId


                LogonContextFound = `
                    $LogonContextFound


                LogonIdentity = `
                    $LogonIdentity

                LogonUserSid = `
                    $LogonUserSid

                LogonType = `
                    $LogonType

                LogonTime = `
                    $LogonTime


                ProcessSecurityRecordId = `
                    $Process.SecurityRecordId

                LogonSecurityRecordId = `
                    $LogonRecordId


                EvidenceBasis = if (
                    $LogonContextFound
                ) {

                    "SecurityLogonIdMatch"

                }
                else {

                    "NoMatchingSecurityLogon"
                }
            }
        )
    }


    return ,$ProcessLogonContexts
}