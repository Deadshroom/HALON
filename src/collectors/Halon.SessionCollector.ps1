# ---------------------------------------------
# HALON WINDOWS SESSION COLLECTOR
# ---------------------------------------------


function Get-HalonCurrentSessionSnapshot {

    Write-Host "Collecting current Windows session snapshot..."

    $CurrentSessions = @()


    try {

        $QuserOutput = quser 2>$null


        if ($LASTEXITCODE -eq 0 -and $QuserOutput) {

            $SessionLines = `
                $QuserOutput |
                Select-Object -Skip 1


            foreach ($Line in $SessionLines) {

                $CleanLine = `
                    $Line.TrimStart(">").Trim()

                $Parts = `
                    $CleanLine -split '\s{2,}'


                if ($Parts.Count -ge 4) {

                    $UserName    = $Parts[0]

                    $SessionName = $null
                    $SessionId   = $null
                    $State       = $null
                    $IdleTime    = $null
                    $LogonTime   = $null


                    if ($Parts.Count -ge 6) {

                        $SessionName = $Parts[1]
                        $SessionId   = $Parts[2]
                        $State       = $Parts[3]
                        $IdleTime    = $Parts[4]
                        $LogonTime   = $Parts[5]

                    }
                    elseif ($Parts.Count -eq 5) {

                        $SessionId = $Parts[1]
                        $State     = $Parts[2]
                        $IdleTime  = $Parts[3]
                        $LogonTime = $Parts[4]
                    }


                    $CurrentSessions += [PSCustomObject]@{

                        UserName    = $UserName
                        SessionName = $SessionName
                        SessionId   = $SessionId
                        State       = $State
                        IdleTime    = $IdleTime
                        LogonTime   = $LogonTime
                    }
                }
            }
        }
    }
    catch {

        Write-Warning `
            "HALON could not collect current Windows session snapshot."
    }


    return @(
        $CurrentSessions
    )
}


function Get-HalonWindowsSessionEvidence {

    param (
        [datetime]$StartTime
    )


    Write-Host "Collecting Windows session lifecycle evidence..."


    $WindowsSessionEventsRaw = @()

    $CollectionStatus = "Available"
    $CollectionError  = $null


    $LogName = `
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"


    try {

        $WindowsSessionEventsRaw = @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName   = $LogName
                    StartTime = $StartTime

                    Id = @(
                        21,   # Session logon
                        23,   # Session logoff
                        24,   # Session disconnect
                        25    # Session reconnect
                    )
                } `
                -ErrorAction Stop
        )

    }
    catch {

        $ErrorMessage = `
            $_.Exception.Message


        if (
            $ErrorMessage -like
            "*No events were found that match the specified selection criteria*"
        ) {

            $CollectionStatus = `
                "AvailableNoMatchingEvents"

            $CollectionError = $null


            Write-Host `
                "No Windows session lifecycle events found in collection window."

        }
        else {

            $CollectionStatus = `
                "Unavailable"

            $CollectionError = `
                $ErrorMessage


            Write-Warning `
                "HALON could not collect Windows session lifecycle evidence."
        }
    }


    return [PSCustomObject]@{

        Events = @(
            $WindowsSessionEventsRaw
        )

        Status = `
            $CollectionStatus

        Error = `
            $CollectionError

        LogName = `
            $LogName
    }
}