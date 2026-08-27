# ---------------------------------------------
# HALON WINDOWS SESSION NORMALIZER
# ---------------------------------------------


function ConvertTo-HalonWindowsSessionEvidence {

    param (
        $RawEvents
    )


    Write-Host "Normalizing Windows session lifecycle evidence..."


    $WindowsSessionEvents = `
        $RawEvents |
        Sort-Object TimeCreated |
        ForEach-Object {

            $EventData = `
                Get-HalonEventData `
                    -Event $_

            $UserData = `
                Get-HalonUserData `
                    -Event $_


            $SessionUser = `
                $UserData["User"]

            $SessionId = `
                $UserData["SessionID"]

            $SourceAddress = `
                $UserData["Address"]


            switch ($_.Id) {

                21 {
                    $SessionAction = "SessionLogon"
                }

                23 {
                    $SessionAction = "SessionLogoff"
                }

                24 {
                    $SessionAction = "SessionDisconnect"
                }

                25 {
                    $SessionAction = "SessionReconnect"
                }

                default {
                    $SessionAction = "Unknown"
                }
            }


            [PSCustomObject]@{

                TimeCreated = `
                    $_.TimeCreated

                EventID = `
                    $_.Id

                Action = `
                    $SessionAction

                Provider = `
                    $_.ProviderName

                RecordId = `
                    $_.RecordId

                Message = `
                    $_.Message

                EventData = `
                    $EventData

                UserData = `
                    $UserData

                User = `
                    $SessionUser

                SessionId = `
                    $SessionId

                SourceAddress = `
                    $SourceAddress
            }
        }


    return @(
        $WindowsSessionEvents
    )
}