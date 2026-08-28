# ---------------------------------------------
# HALON TIMELINE RECONSTRUCTOR
# ---------------------------------------------


function Get-HalonTimeline {

    param (
        $Events
    )


    Write-Host "Building chronological timeline..."


    # -----------------------------------------
    # BASE CHRONOLOGICAL TIMELINE
    # -----------------------------------------

    $Timeline = @(
        $Events |
            Sort-Object OccurrenceTime |
            ForEach-Object {

                $Event = $_
                $AnchorType = $null


                switch ($Event.EventID) {

                    41 {

                        if (
                            $Event.Provider -like
                            "*Kernel-Power*"
                        ) {

                            $AnchorType = `
                                "UnexpectedRestart"
                        }
                    }


                    1001 {

                        if (
                            $Event.Provider -like
                            "*BugCheck*"
                        ) {

                            $AnchorType = `
                                "BugCheck"
                        }
                    }


                    1074 {

                        if (
                            $Event.Provider -like
                            "*User32*"
                        ) {

                            $AnchorType = `
                                "PlannedShutdownOrRestart"
                        }
                    }


                    6005 {

                        if (
                            $Event.Provider -eq
                            "EventLog"
                        ) {

                            $AnchorType = `
                                "EventLogStarted"
                        }
                    }


                    6006 {

                        if (
                            $Event.Provider -eq
                            "EventLog"
                        ) {

                            $AnchorType = `
                                "EventLogStopped"
                        }
                    }


                    6008 {

                        if (
                            $Event.Provider -eq
                            "EventLog"
                        ) {

                            $AnchorType = `
                                "UnexpectedShutdownConfirmed"
                        }
                    }
                }


                [PSCustomObject]@{

                    LoggedTime = `
                        $Event.LoggedTime

                    OccurrenceTime = `
                        $Event.OccurrenceTime

                    LogName = `
                        $Event.LogName

                    RecordId = `
                        $Event.RecordId

                    Level = `
                        $Event.Level

                    EventID = `
                        $Event.EventID

                    Provider = `
                        $Event.Provider

                    AnchorType = `
                        $AnchorType

                    Message = `
                        $Event.Message

                    Category = `
                        $Event.Category

                    EventSignature = `
                        $Event.EventSignature

                    SeverityScore = `
                        $Event.SeverityScore

                    EventUserSid = `
                        $Event.EventUserSid

                    EventUser = `
                        $Event.EventUser

                    StructuredEventData = `
                        $Event.StructuredEventData
                }
            }
    )


    # -----------------------------------------
    # BOOT SESSION RECONSTRUCTION
    # -----------------------------------------

    Write-Host "Reconstructing boot sessions..."


    $BootSessionNumber = 0
    $BootSessionActive = $false


    foreach ($Event in $Timeline) {

        if (
            $Event.Provider -eq "EventLog" -and
            $Event.EventID -eq 6005
        ) {

            $BootSessionNumber++
            $BootSessionActive = $true
        }


        if ($BootSessionNumber -eq 0) {

            $BootSessionId = `
                "PRE_COLLECTION_BOOT"
        }
        else {

            $BootSessionId = `
                "BOOT_{0:D3}" -f `
                    $BootSessionNumber
        }


        $Event |
            Add-Member `
                -NotePropertyName BootSessionId `
                -NotePropertyValue $BootSessionId `
                -Force


        $Event |
            Add-Member `
                -NotePropertyName BootSessionActive `
                -NotePropertyValue $BootSessionActive `
                -Force


        if (
            $Event.Provider -eq "EventLog" -and
            $Event.EventID -eq 6006
        ) {

            $BootSessionActive = $false
        }
    }


    # -----------------------------------------
    # EVENT-TO-EVENT CHRONOLOGY
    # -----------------------------------------

    Write-Host "Calculating event chronology deltas..."


    $PreviousEventTime = $null


    foreach ($Event in $Timeline) {

        $EventTime = `
            [datetime]$Event.OccurrenceTime


        if ($null -eq $PreviousEventTime) {

            $SecondsSincePreviousEvent = `
                $null
        }
        else {

            $SecondsSincePreviousEvent = `
                [math]::Round(
                    (
                        $EventTime -
                        $PreviousEventTime
                    ).TotalSeconds,
                    3
                )
        }


        $Event |
            Add-Member `
                -NotePropertyName SecondsSincePreviousEvent `
                -NotePropertyValue $SecondsSincePreviousEvent `
                -Force


        $PreviousEventTime = `
            $EventTime
    }


    # -----------------------------------------
    # COLLECTION RECURRENCE
    # -----------------------------------------

    Write-Host "Calculating event recurrence..."


    $CollectionOccurrenceCounts = @{}


    $Timeline |
        Group-Object EventSignature |
        ForEach-Object {

            if (
                -not [string]::IsNullOrWhiteSpace(
                    $_.Name
                )
            ) {

                $CollectionOccurrenceCounts[
                    $_.Name
                ] = $_.Count
            }
        }


    foreach ($Event in $Timeline) {

        $OccurrenceCount = 0


        if (
            -not [string]::IsNullOrWhiteSpace(
                $Event.EventSignature
            ) -and

            $CollectionOccurrenceCounts.ContainsKey(
                $Event.EventSignature
            )
        ) {

            $OccurrenceCount = `
                $CollectionOccurrenceCounts[
                    $Event.EventSignature
                ]
        }


        $Event |
            Add-Member `
                -NotePropertyName OccurrencesInCollection `
                -NotePropertyValue $OccurrenceCount `
                -Force
    }


    return $Timeline
}