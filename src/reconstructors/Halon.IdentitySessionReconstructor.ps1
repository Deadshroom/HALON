# ---------------------------------------------
# HALON IDENTITY SESSION RECONSTRUCTOR
# ---------------------------------------------


function Get-HalonIdentitySessions {

    param (
        $IdentityEvents
    )


    Write-Host "Reconstructing identity sessions..."


    $IdentitySessions = @()


    $InteractiveLogons = $IdentityEvents |
        Where-Object {

            $_.Action -eq "Logon" -and

            (
                Test-HalonInteractiveLogonType `
                    -LogonType $_.LogonType
            )
        } |
        Sort-Object TimeCreated


    foreach ($Logon in $InteractiveLogons) {

        $LogonTime = `
            [datetime]$Logon.TimeCreated

        $LogonId = `
            $Logon.LogonId


        # Find the first matching end-of-logon-context
        # event occurring after this logon.

        $SessionEndEvent = $IdentityEvents |
            Where-Object {

                $_.LogonId -eq $LogonId -and

                [datetime]$_.TimeCreated -gt `
                    $LogonTime -and

                $_.Action -in @(
                    "Logoff",
                    "UserInitiatedLogoff"
                )

            } |
            Sort-Object TimeCreated |
            Select-Object -First 1


        if ($null -ne $SessionEndEvent) {

            $SessionEnd = `
                [datetime]$SessionEndEvent.TimeCreated

            $SessionState = `
                "Closed"

            $EndReason = `
                $SessionEndEvent.Action


            $DurationMinutes = [math]::Round(
                (
                    $SessionEnd -
                    $LogonTime
                ).TotalMinutes,
                2
            )

        }
        else {

            $SessionEnd = $null

            $SessionState = `
                "OpenAtCollectionEnd"

            $EndReason = $null

            $DurationMinutes = $null
        }


        $IdentitySessions += [PSCustomObject]@{

            Identity = `
                $Logon.Identity

            IdentityClass = `
                $Logon.IdentityClass

            UserName = `
                $Logon.UserName

            Domain = `
                $Logon.Domain

            UserSid = `
                $Logon.UserSid

            LogonId = `
                $Logon.LogonId

            LogonType = `
                $Logon.LogonType


            SessionStart = `
                $LogonTime

            SessionEnd = `
                $SessionEnd

            DurationMinutes = `
                $DurationMinutes


            State = `
                $SessionState

            EndReason = `
                $EndReason


            LogonRecordId = `
                $Logon.RecordId

            LogoffRecordId = if (
                $null -ne $SessionEndEvent
            ) {

                $SessionEndEvent.RecordId

            }
            else {

                $null
            }
        }
    }


    return @(
        $IdentitySessions
    )
}