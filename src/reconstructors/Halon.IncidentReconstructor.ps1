# ---------------------------------------------
# HALON INCIDENT RECONSTRUCTOR
# ---------------------------------------------


function Get-HalonIncidentAnchors {

    param (
        $Timeline
    )


    return @(
        $Timeline |
            Where-Object {
                $_.AnchorType -eq "UnexpectedShutdownConfirmed"
            }
    )
}


function Get-HalonIncidentContexts {

    param (
        $Timeline,

        $IncidentAnchors
    )


    Write-Host "Building full incident context..."


    $IncidentContexts = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Anchor in $IncidentAnchors) {

        $AnchorTime = `
            [datetime]$Anchor.OccurrenceTime


        $ContextEvents = @(
            $Timeline |
                ForEach-Object {

                    $EventTime = `
                        [datetime]$_.OccurrenceTime


                    $MinutesFromIncident = `
                        [math]::Round(
                            (
                                $EventTime -
                                $AnchorTime
                            ).TotalMinutes,
                            3
                        )


                    if (
                        $_.RecordId -eq
                        $Anchor.RecordId
                    ) {

                        $IncidentPhase = `
                            "INCIDENT"
                    }
                    elseif (
                        $EventTime -lt
                        $AnchorTime
                    ) {

                        $IncidentPhase = `
                            "PRE_INCIDENT"
                    }
                    else {

                        $IncidentPhase = `
                            "POST_INCIDENT"
                    }


                    $WithinFocusedWindow = (
                        $MinutesFromIncident -ge -30 -and
                        $MinutesFromIncident -le 10
                    )


                    [PSCustomObject]@{

                        OccurrenceTime = (
                            [datetime]$_.OccurrenceTime
                        ).ToString(
                            "MM/dd/yyyy HH:mm:ss"
                        )

                        LoggedTime = (
                            [datetime]$_.LoggedTime
                        ).ToString(
                            "MM/dd/yyyy HH:mm:ss"
                        )

                        MinutesFromIncident = `
                            $MinutesFromIncident

                        IncidentPhase = `
                            $IncidentPhase

                        WithinFocusedWindow = `
                            $WithinFocusedWindow


                        BootSessionId = `
                            $_.BootSessionId

                        BootSessionActive = `
                            $_.BootSessionActive

                        SecondsSincePreviousEvent = `
                            $_.SecondsSincePreviousEvent


                        LogName = `
                            $_.LogName

                        RecordId = `
                            $_.RecordId

                        Provider = `
                            $_.Provider

                        EventID = `
                            $_.EventID

                        Level = `
                            $_.Level

                        SeverityScore = `
                            $_.SeverityScore

                        Category = `
                            $_.Category

                        EventSignature = `
                            $_.EventSignature

                        OccurrencesInCollection = `
                            $_.OccurrencesInCollection

                        AnchorType = `
                            $_.AnchorType

                        Message = `
                            $_.Message
                    }
                }
        )


        $IncidentContexts.Add(
            [PSCustomObject]@{

                IncidentType = `
                    "UnexpectedShutdown"

                AnchorTime = `
                    $AnchorTime.ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )

                CollectionEventCount = `
                    $ContextEvents.Count

                Events = `
                    $ContextEvents
            }
        )
    }


    return $IncidentContexts.ToArray()
}


function Get-HalonIncidentWindows {

    param (
        $Timeline,

        $IncidentAnchors
    )


    Write-Host "Building enriched incident windows..."


    $IncidentWindows = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($Anchor in $IncidentAnchors) {

        $AnchorTime = `
            [datetime]$Anchor.OccurrenceTime


        $WindowStart = `
            $AnchorTime.AddMinutes(-30)

        $WindowEnd = `
            $AnchorTime.AddMinutes(10)


        # -------------------------------------
        # EVENTS INSIDE FOCUSED WINDOW
        # -------------------------------------

        $WindowEventsBase = @(
            $Timeline |
                Where-Object {

                    $EventTime = `
                        [datetime]$_.OccurrenceTime


                    $EventTime -ge $WindowStart -and
                    $EventTime -le $WindowEnd
                }
        )


        # -------------------------------------
        # RECURRENCE INSIDE INCIDENT WINDOW
        # -------------------------------------

        $IncidentOccurrenceCounts = @{}


        $WindowEventsBase |
            Group-Object EventSignature |
            ForEach-Object {

                $IncidentOccurrenceCounts[
                    $_.Name
                ] = $_.Count
            }


        # -------------------------------------
        # ENRICH INCIDENT EVENTS
        # -------------------------------------

        $WindowEvents = @(
            $WindowEventsBase |
                ForEach-Object {

                    $EventTime = `
                        [datetime]$_.OccurrenceTime


                    $MinutesFromIncident = `
                        [math]::Round(
                            (
                                $EventTime -
                                $AnchorTime
                            ).TotalMinutes,
                            2
                        )


                    if (
                        $_.RecordId -eq
                        $Anchor.RecordId
                    ) {

                        $IncidentPhase = `
                            "INCIDENT"

                        $Position = `
                            "ANCHOR"
                    }
                    elseif (
                        $EventTime -lt
                        $AnchorTime
                    ) {

                        $IncidentPhase = `
                            "PRE_INCIDENT"

                        $Position = `
                            "BEFORE"
                    }
                    else {

                        $IncidentPhase = `
                            "POST_INCIDENT"

                        $Position = `
                            "AFTER"
                    }


                    $LifecycleContext = `
                        Get-HalonLifecycleContext `
                            -Event $_


                    [PSCustomObject]@{

                        OccurrenceTime = `
                            $_.OccurrenceTime

                        LoggedTime = `
                            $_.LoggedTime


                        MinutesFromIncident = `
                            $MinutesFromIncident

                        IncidentPhase = `
                            $IncidentPhase

                        Position = `
                            $Position


                        Category = `
                            $_.Category

                        Level = `
                            $_.Level

                        SeverityScore = `
                            $_.SeverityScore

                        EventID = `
                            $_.EventID

                        Provider = `
                            $_.Provider


                        LifecycleContext = `
                            $LifecycleContext

                        EventSignature = `
                            $_.EventSignature

                        OccurrencesInCollection = `
                            $_.OccurrencesInCollection

                        OccurrencesInIncidentWindow = `
                            $IncidentOccurrenceCounts[
                                $_.EventSignature
                            ]


                        AnchorType = `
                            $_.AnchorType

                        Message = `
                            $_.Message


                        BootSessionId = `
                            $_.BootSessionId

                        BootSessionActive = `
                            $_.BootSessionActive

                        SecondsSincePreviousEvent = `
                            $_.SecondsSincePreviousEvent
                    }
                }
        )


        $IncidentWindows.Add(
            [PSCustomObject]@{

                IncidentType = `
                    "UnexpectedShutdown"

                AnchorTime = `
                    $AnchorTime

                WindowStart = `
                    $WindowStart

                WindowEnd = `
                    $WindowEnd

                EventCount = `
                    $WindowEvents.Count

                Events = `
                    $WindowEvents
            }
        )
    }


    return $IncidentWindows.ToArray()
}