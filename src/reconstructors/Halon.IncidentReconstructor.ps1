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

function Get-HalonIncidentDiagnosticArtifacts {

    param (
        $IncidentEvents,

        $CanonicalEventByRecordId
    )


    $DiagnosticArtifacts = `
        [System.Collections.Generic.List[object]]::new()


    foreach ($IncidentEvent in @($IncidentEvents)) {

        # -------------------------------------
        # CURRENT PROVEN CAPABILITY
        #
        # Microsoft-Windows-WER-SystemErrorReporting
        # Event 1001
        #
        # param1 = raw BugCheck tuple
        # param2 = dump path
        # param3 = Windows report ID
        # -------------------------------------

        if (
            $IncidentEvent.EventID -ne 1001 -or
            $IncidentEvent.Provider -ne
                "Microsoft-Windows-WER-SystemErrorReporting"
        ) {

            continue
        }


        if ($null -eq $IncidentEvent.RecordId) {
            continue
        }


        $RecordKey = `
            [string]$IncidentEvent.RecordId


        if (
            -not $CanonicalEventByRecordId.ContainsKey(
                $RecordKey
            )
        ) {

            continue
        }


        $SourceEvent = `
            $CanonicalEventByRecordId[
                $RecordKey
            ]


        $StructuredData = `
            $SourceEvent.StructuredEventData


        if ($null -eq $StructuredData) {
            continue
        }


        $BugCheckRaw = `
            $StructuredData.param1

        $DumpPath = `
            $StructuredData.param2

        $ReportId = `
            $StructuredData.param3


        if (
            [string]::IsNullOrWhiteSpace(
                [string]$DumpPath
            )
        ) {

            continue
        }


        $ArtifactType = `
            "UnknownDiagnosticArtifact"


        if (
            [System.IO.Path]::GetExtension(
                [string]$DumpPath
            ) -ieq ".dmp"
        ) {

            $ArtifactType = `
                "WindowsMinidump"
        }


        $OccurrenceTime = $null

        if ($null -ne $SourceEvent.OccurrenceTime) {

            $OccurrenceTime = (
                [datetime]$SourceEvent.OccurrenceTime
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )
        }


        $LoggedTime = $null

        if ($null -ne $SourceEvent.LoggedTime) {

            $LoggedTime = (
                [datetime]$SourceEvent.LoggedTime
            ).ToString(
                "MM/dd/yyyy HH:mm:ss"
            )
        }


        $DiagnosticArtifacts.Add(
            [PSCustomObject]@{

                Relationship = `
                    "ProducedDiagnosticArtifact"


                ArtifactType = `
                    $ArtifactType

                ArtifactPath = `
                    [string]$DumpPath

                ReportId = `
                    [string]$ReportId

                BugCheckRaw = `
                    [string]$BugCheckRaw


                EvidenceSource = `
                    [PSCustomObject]@{

                        RecordId = `
                            $SourceEvent.RecordId

                        EventID = `
                            $SourceEvent.EventID

                        Provider = `
                            $SourceEvent.Provider

                        OccurrenceTime = `
                            $OccurrenceTime

                        LoggedTime = `
                            $LoggedTime
                    }


                IncidentAssociation = `
                    [PSCustomObject]@{

                        RecordId = `
                            $IncidentEvent.RecordId

                        EvidenceBasis = `
                            "IncidentWindowRecordIdMatch"
                    }


                EvidenceBasis = `
                    "CanonicalEventStructuredData"
            }
        )
    }


    return $DiagnosticArtifacts.ToArray()
}

function Get-HalonIncidentWindows {

    param (
        $Timeline,

        $IncidentAnchors,

        $CanonicalEvents
    )


    Write-Host "Building enriched incident windows..."


    $IncidentWindows = `
        [System.Collections.Generic.List[object]]::new()

# -----------------------------------------
# CANONICAL EVENT RECORD INDEX
#
# Stable RecordId bridge back to complete
# normalized event evidence.
# -----------------------------------------

    $CanonicalEventByRecordId = @{}


    foreach (
        $CanonicalEvent in
        @($CanonicalEvents)
    ) {

        if ($null -eq $CanonicalEvent.RecordId) {
            continue
        }


        $CanonicalEventByRecordId[
            [string]$CanonicalEvent.RecordId
        ] = $CanonicalEvent
    }

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
                        
                            RecordId = `
                            $_.RecordId

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

# -------------------------------------
# DIAGNOSTIC ARTIFACT RECONSTRUCTION
# -------------------------------------

        $DiagnosticArtifacts = `
            Get-HalonIncidentDiagnosticArtifacts `
                -IncidentEvents $WindowEventsBase `
                -CanonicalEventByRecordId `
                    $CanonicalEventByRecordId

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
                     
                DiagnosticArtifactCount = `
                    @(
                        $DiagnosticArtifacts
                    ).Count

                DiagnosticArtifacts = `
                    @(
                        $DiagnosticArtifacts
                    )
            }
        )
    }


    return $IncidentWindows.ToArray()
}