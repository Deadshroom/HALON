# ---------------------------------------------
# HALON WINDOWS SESSION RECONSTRUCTOR
# ---------------------------------------------


function Get-HalonWindowsSessions {

    param (
        $WindowsSessionEvents
    )


    Write-Host "Reconstructing Windows sessions..."


    $WindowsSessions = @()


    $SessionLogons = $WindowsSessionEvents |
        Where-Object {
            $_.Action -eq "SessionLogon"
        } |
        Sort-Object TimeCreated


    foreach ($Logon in $SessionLogons) {

        $SessionStart = `
            [datetime]$Logon.TimeCreated

        $SessionId = `
            $Logon.SessionId

        $SessionUser = `
            $Logon.User


        # Find the first matching logoff occurring
        # after this session logon.

        $SessionLogoff = $WindowsSessionEvents |
            Where-Object {

                $_.Action -eq "SessionLogoff" -and

                $_.SessionId -eq $SessionId -and

                $_.User -eq $SessionUser -and

                [datetime]$_.TimeCreated -gt `
                    $SessionStart

            } |
            Sort-Object TimeCreated |
            Select-Object -First 1


        if ($null -ne $SessionLogoff) {

            $SessionEnd = `
                [datetime]$SessionLogoff.TimeCreated

            $SessionState = `
                "Closed"

        }
        else {

            $SessionEnd = $null

            $SessionState = `
                "OpenAtCollectionEnd"
        }


        # Collect disconnect/reconnect activity
        # belonging to this session interval.

        $StateEvents = $WindowsSessionEvents |
            Where-Object {

                $_.SessionId -eq $SessionId -and

                $_.User -eq $SessionUser -and

                $_.Action -in @(
                    "SessionDisconnect",
                    "SessionReconnect"
                ) -and

                [datetime]$_.TimeCreated -ge `
                    $SessionStart -and

                (
                    $null -eq $SessionEnd -or

                    [datetime]$_.TimeCreated -le `
                        $SessionEnd
                )
            } |
            Sort-Object TimeCreated


        $WindowsSessions += [PSCustomObject]@{

            User = `
                $SessionUser

            SessionId = `
                $SessionId

            SourceAddress = `
                $Logon.SourceAddress


            SessionStart = `
                $SessionStart

            SessionEnd = `
                $SessionEnd


            State = `
                $SessionState


            LogonRecordId = `
                $Logon.RecordId

            LogoffRecordId = if (
                $null -ne $SessionLogoff
            ) {

                $SessionLogoff.RecordId

            }
            else {

                $null
            }


            StateEvents = @(
                $StateEvents
            )
        }
    }


    return @(
        $WindowsSessions
    )
}