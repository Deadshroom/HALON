# ---------------------------------------------
# HALON PROCESS EVIDENCE NORMALIZER
# ---------------------------------------------


function ConvertTo-HalonProcessCreationEvidence {

    param (
        $RawEvents
    )


    Write-Host "Normalizing historical process creation evidence..."


    $ProcessCreationEvents = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Event in $RawEvents) {

        try {

            $EventData = `
                Get-HalonEventData `
                    -Event $Event


            # ---------------------------------
            # SUBJECT / CREATOR IDENTITY
            # ---------------------------------

            $SubjectUserSid = `
                $EventData["SubjectUserSid"]

            $SubjectUserName = `
                $EventData["SubjectUserName"]

            $SubjectDomainName = `
                $EventData["SubjectDomainName"]

            $SubjectLogonId = `
                $EventData["SubjectLogonId"]


            if (
                -not [string]::IsNullOrWhiteSpace(
                    $SubjectDomainName
                ) -and

                -not [string]::IsNullOrWhiteSpace(
                    $SubjectUserName
                )
            ) {

                $SubjectIdentity = `
                    "$SubjectDomainName\$SubjectUserName"
            }
            else {

                $SubjectIdentity = `
                    $SubjectUserName
            }


            # ---------------------------------
            # NEW PROCESS
            # ---------------------------------

            $ProcessIdRaw = `
                $EventData["NewProcessId"]

            $ProcessIdDecimal = `
                Convert-HalonHexToInt64 `
                    -Value $ProcessIdRaw

            $ProcessName = `
                $EventData["NewProcessName"]


            # ---------------------------------
            # CREATOR / PARENT PROCESS
            # ---------------------------------

            $ParentProcessIdRaw = `
                $EventData["ProcessId"]

            $ParentProcessIdDecimal = `
                Convert-HalonHexToInt64 `
                    -Value $ParentProcessIdRaw

            $ParentProcessName = `
                $EventData["ParentProcessName"]


            # ---------------------------------
            # TARGET IDENTITY
            # ---------------------------------

            $TargetUserSid = `
                $EventData["TargetUserSid"]

            $TargetUserName = `
                $EventData["TargetUserName"]

            $TargetDomainName = `
                $EventData["TargetDomainName"]

            $TargetLogonId = `
                $EventData["TargetLogonId"]


            if (
                -not [string]::IsNullOrWhiteSpace(
                    $TargetDomainName
                ) -and

                $TargetDomainName -ne "-" -and

                -not [string]::IsNullOrWhiteSpace(
                    $TargetUserName
                ) -and

                $TargetUserName -ne "-"
            ) {

                $TargetIdentity = `
                    "$TargetDomainName\$TargetUserName"
            }
            else {

                $TargetIdentity = $null
            }


            # ---------------------------------
            # NORMALIZED PROCESS EVENT
            # ---------------------------------

            $ProcessCreationEvents.Add(
                [PSCustomObject]@{

                    TimeCreated = `
                        $Event.TimeCreated

                    SecurityRecordId = `
                        $Event.RecordId

                    EventID = `
                        $Event.Id


                    SubjectIdentity = `
                        $SubjectIdentity

                    SubjectUserSid = `
                        $SubjectUserSid

                    SubjectUserName = `
                        $SubjectUserName

                    SubjectDomainName = `
                        $SubjectDomainName

                    SubjectLogonId = `
                        $SubjectLogonId


                    ProcessIdRaw = `
                        $ProcessIdRaw

                    ProcessIdDecimal = `
                        $ProcessIdDecimal

                    ProcessName = `
                        $ProcessName


                    ParentProcessIdRaw = `
                        $ParentProcessIdRaw

                    ParentProcessIdDecimal = `
                        $ParentProcessIdDecimal

                    ParentProcessName = `
                        $ParentProcessName


                    TargetIdentity = `
                        $TargetIdentity

                    TargetUserSid = `
                        $TargetUserSid

                    TargetUserName = `
                        $TargetUserName

                    TargetDomainName = `
                        $TargetDomainName

                    TargetLogonId = `
                        $TargetLogonId


                    CommandLine = `
                        $EventData["CommandLine"]

                    TokenElevationType = `
                        $EventData["TokenElevationType"]

                    MandatoryLabel = `
                        $EventData["MandatoryLabel"]
                }
            )
        }
        finally {

            # EventLogRecord owns unmanaged resources.
            # Once HALON has normalized the evidence,
            # the raw record is no longer needed.

            if ($null -ne $Event) {

                $Event.Dispose()
            }
        }
    }


    return ,$ProcessCreationEvents
}