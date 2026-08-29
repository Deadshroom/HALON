# ---------------------------------------------
# HALON IDENTITY EVIDENCE NORMALIZER
# ---------------------------------------------


function ConvertTo-HalonIdentityEvidence {

    param (
        $RawEvents
    )


    Write-Host "Normalizing identity evidence..."


    $IdentityEvents = $RawEvents |
        Sort-Object TimeCreated |
        ForEach-Object {

            $EventData = Get-HalonEventData `
                -Event $_


            $Action = "Unknown"

            $UserName = $null
            $Domain   = $null

            $UserSid  = $null

            $LogonId   = $null
            $LogonType = $null

            $SessionName   = $null
            $ClientName    = $null
            $ClientAddress = $null


            switch ($_.Id) {

                4624 {

                    $Action = "Logon"

                    $UserName = `
                        $EventData["TargetUserName"]

                    $Domain = `
                        $EventData["TargetDomainName"]

                    $LogonId = `
                        $EventData["TargetLogonId"]

                    $LogonType = `
                        $EventData["LogonType"]

                    $UserSid = `
                        $EventData["TargetUserSid"]
                }


                4634 {

                    $Action = "Logoff"

                    $UserName = `
                        $EventData["TargetUserName"]

                    $Domain = `
                        $EventData["TargetDomainName"]

                    $LogonId = `
                        $EventData["TargetLogonId"]

                    $LogonType = `
                        $EventData["LogonType"]

                    $UserSid = `
                        $EventData["TargetUserSid"]
                }


                4647 {

                    $Action = "UserInitiatedLogoff"

                    $UserName = `
                        $EventData["SubjectUserName"]

                    $Domain = `
                        $EventData["SubjectDomainName"]

                    $LogonId = `
                        $EventData["SubjectLogonId"]

                    $UserSid = `
                        $EventData["SubjectUserSid"]
                }


                4778 {

                    $Action = "SessionReconnect"

                    $UserName = `
                        $EventData["AccountName"]

                    $Domain = `
                        $EventData["AccountDomain"]

                    $LogonId = `
                        $EventData["LogonID"]

                    $SessionName = `
                        $EventData["SessionName"]

                    $ClientName = `
                        $EventData["ClientName"]

                    $ClientAddress = `
                        $EventData["ClientAddress"]
                }


                4779 {

                    $Action = "SessionDisconnect"

                    $UserName = `
                        $EventData["AccountName"]

                    $Domain = `
                        $EventData["AccountDomain"]

                    $LogonId = `
                        $EventData["LogonID"]

                    $SessionName = `
                        $EventData["SessionName"]

                    $ClientName = `
                        $EventData["ClientName"]

                    $ClientAddress = `
                        $EventData["ClientAddress"]
                }
            }


            if (
                -not [string]::IsNullOrWhiteSpace($Domain) -and
                -not [string]::IsNullOrWhiteSpace($UserName)
            ) {

                $Identity = "$Domain\$UserName"

            }
            else {

                $Identity = $UserName
            }


            $IdentityClass = Get-HalonIdentityClass `
                -UserSid $UserSid `
                -Identity $Identity


            [PSCustomObject]@{

                TimeCreated = `
                    $_.TimeCreated

                EventID = `
                    $_.Id

                Action = `
                    $Action


                Identity = `
                    $Identity

                IdentityClass = `
                    $IdentityClass

                UserName = `
                    $UserName

                Domain = `
                    $Domain

                UserSid = `
                    $UserSid


                LogonId = `
                    $LogonId

                LogonType = `
                    $LogonType


                SessionName = `
                    $SessionName

                ClientName = `
                    $ClientName

                ClientAddress = `
                    $ClientAddress


                RecordId = `
                    $_.RecordId
            }
        }


    return @(
        $IdentityEvents
    )
}