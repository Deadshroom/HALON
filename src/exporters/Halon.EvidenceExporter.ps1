# ---------------------------------------------
# HALON EVIDENCE EXPORT SHAPERS
# ---------------------------------------------

function ConvertTo-HalonDateString {

    param (
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    return (
        [datetime]$Value
    ).ToString(
        "MM/dd/yyyy HH:mm:ss"
    )
}
function ConvertTo-HalonProcessCreationExport {

    param (
        $ProcessCreationEvents
    )


    return @(
        $ProcessCreationEvents |
            ForEach-Object {

                [PSCustomObject]@{

                    TimeCreated = (
                        [datetime]$_.TimeCreated
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                    SecurityRecordId = `
                        $_.SecurityRecordId

                    EventID = `
                        $_.EventID


                    SubjectIdentity = `
                        $_.SubjectIdentity

                    SubjectUserSid = `
                        $_.SubjectUserSid

                    SubjectLogonId = `
                        $_.SubjectLogonId


                    ProcessIdRaw = `
                        $_.ProcessIdRaw

                    ProcessIdDecimal = `
                        $_.ProcessIdDecimal

                    ProcessName = `
                        $_.ProcessName


                    ParentProcessIdRaw = `
                        $_.ParentProcessIdRaw

                    ParentProcessIdDecimal = `
                        $_.ParentProcessIdDecimal

                    ParentProcessName = `
                        $_.ParentProcessName


                    TargetIdentity = `
                        $_.TargetIdentity

                    TargetUserSid = `
                        $_.TargetUserSid

                    TargetLogonId = `
                        $_.TargetLogonId


                    CommandLine = `
                        $_.CommandLine

                    TokenElevationType = `
                        $_.TokenElevationType

                    MandatoryLabel = `
                        $_.MandatoryLabel
                }
            }
    )
}


function ConvertTo-HalonIdentitySessionExport {

    param (
        $IdentitySessions
    )


    return @(
        $IdentitySessions |
            ForEach-Object {

                [PSCustomObject]@{

                    Identity = `
                        $_.Identity

                    IdentityClass = `
                        $_.IdentityClass

                    UserName = `
                        $_.UserName

                    Domain = `
                        $_.Domain

                    UserSid = `
                        $_.UserSid

                    LogonId = `
                        $_.LogonId

                    LogonType = `
                        $_.LogonType


                    SessionStart = (
                        [datetime]$_.SessionStart
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                    SessionEnd = if (
                        $null -ne $_.SessionEnd
                    ) {

                        (
                            [datetime]$_.SessionEnd
                        ).ToString(
                            "MM/dd/yyyy HH:mm:ss"
                        )
                    }
                    else {

                        $null
                    }


                    DurationMinutes = `
                        $_.DurationMinutes

                    State = `
                        $_.State

                    EndReason = `
                        $_.EndReason


                    LogonRecordId = `
                        $_.LogonRecordId

                    LogoffRecordId = `
                        $_.LogoffRecordId
                }
            }
    )
}


function ConvertTo-HalonWindowsSessionExport {

    param (
        $WindowsSessions
    )


    return @(
        $WindowsSessions |
            ForEach-Object {

                [PSCustomObject]@{

                    User = `
                        $_.User

                    SessionId = `
                        $_.SessionId

                    SourceAddress = `
                        $_.SourceAddress


                    SessionStart = (
                        [datetime]$_.SessionStart
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                    SessionEnd = if (
                        $null -ne $_.SessionEnd
                    ) {

                        (
                            [datetime]$_.SessionEnd
                        ).ToString(
                            "MM/dd/yyyy HH:mm:ss"
                        )
                    }
                    else {

                        $null
                    }


                    State = `
                        $_.State


                    LogonRecordId = `
                        $_.LogonRecordId

                    LogoffRecordId = `
                        $_.LogoffRecordId


                    StateEvents = @(
                        $_.StateEvents |
                            ForEach-Object {

                                [PSCustomObject]@{

                                    TimeCreated = (
                                        [datetime]$_.TimeCreated
                                    ).ToString(
                                        "MM/dd/yyyy HH:mm:ss"
                                    )

                                    Action = `
                                        $_.Action

                                    RecordId = `
                                        $_.RecordId
                                }
                            }
                    )
                }
            }
    )
}


function ConvertTo-HalonProcessLogonContextExport {

    param (
        $ProcessLogonContexts
    )


    return @(
        $ProcessLogonContexts |
            ForEach-Object {

                [PSCustomObject]@{

                    ProcessTime = (
                        [datetime]$_.ProcessTime
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                    ProcessId = `
                        $_.ProcessId

                    ProcessIdRaw = `
                        $_.ProcessIdRaw

                    ProcessName = `
                        $_.ProcessName


                    ParentProcessId = `
                        $_.ParentProcessId

                    ParentProcessName = `
                        $_.ParentProcessName


                    SubjectIdentity = `
                        $_.SubjectIdentity

                    SubjectUserSid = `
                        $_.SubjectUserSid

                    SubjectLogonId = `
                        $_.SubjectLogonId


                    LogonContextFound = `
                        $_.LogonContextFound

                    LogonIdentity = `
                        $_.LogonIdentity

                    LogonUserSid = `
                        $_.LogonUserSid

                    LogonType = `
                        $_.LogonType


                    LogonTime = if (
                        $null -ne $_.LogonTime
                    ) {

                        (
                            [datetime]$_.LogonTime
                        ).ToString(
                            "MM/dd/yyyy HH:mm:ss"
                        )
                    }
                    else {

                        $null
                    }


                    ProcessSecurityRecordId = `
                        $_.ProcessSecurityRecordId

                    LogonSecurityRecordId = `
                        $_.LogonSecurityRecordId


                    EvidenceBasis = `
                        $_.EvidenceBasis
                }
            }
    )
}


function ConvertTo-HalonEventProcessCorrelationExport {

    param (
        $EventProcessCorrelations
    )


    return @(
        $EventProcessCorrelations |
            ForEach-Object {

                [PSCustomObject]@{

                    EventTime = (
                        [datetime]$_.EventTime
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                    EventRecordId = `
                        $_.EventRecordId

                    EventProvider = `
                        $_.EventProvider

                    EventID = `
                        $_.EventID

                    EventLevel = `
                        $_.EventLevel


                    ReferencedProcessId = `
                        $_.ReferencedProcessId

                    ReferencedProcessName = `
                        $_.ReferencedProcessName

                    ReferencedProcessPath = `
                        $_.ReferencedProcessPath


                    HistoricalProcessFound = `
                        $_.HistoricalProcessFound

                    MatchBasis = `
                        $_.MatchBasis

                    ProcessAgeAtEventSeconds = `
                        $_.ProcessAgeAtEventSeconds


                    HistoricalProcessCreated = if (
                        $null -ne
                        $_.HistoricalProcessCreated
                    ) {

                        (
                            [datetime]$_.HistoricalProcessCreated
                        ).ToString(
                            "MM/dd/yyyy HH:mm:ss"
                        )
                    }
                    else {

                        $null
                    }


                    HistoricalProcessName = `
                        $_.HistoricalProcessName

                    HistoricalProcessSecurityRecordId = `
                        $_.HistoricalProcessSecurityRecordId
                        
                    ParentProcessId = `
                        $_.ParentProcessId

                    ParentProcessName = `
                        $_.ParentProcessName


                    SubjectIdentity = `
                        $_.SubjectIdentity

                    SubjectUserSid = `
                        $_.SubjectUserSid

                    SubjectLogonId = `
                        $_.SubjectLogonId


                    LogonContextFound = `
                        $_.LogonContextFound

                    LogonIdentity = `
                        $_.LogonIdentity


                    EvidenceBasis = `
                        $_.EvidenceBasis
                }
            }
    )
}


function ConvertTo-HalonTimelineExport {

    param (
        $Timeline
    )


    return @(
        $Timeline |
            ForEach-Object {

                [PSCustomObject]@{

                    LoggedTime = (
                        [datetime]$_.LoggedTime
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                    OccurrenceTime = (
                        [datetime]$_.OccurrenceTime
                    ).ToString(
                        "MM/dd/yyyy HH:mm:ss"
                    )


                    LogName = `
                        $_.LogName

                    RecordId = `
                        $_.RecordId

                    Level = `
                        $_.Level

                    EventID = `
                        $_.EventID

                    Provider = `
                        $_.Provider

                    AnchorType = `
                        $_.AnchorType

                    Message = `
                        $_.Message


                    Category = `
                        $_.Category

                    EventSignature = `
                        $_.EventSignature

                    SeverityScore = `
                        $_.SeverityScore


                    EventUserSid = `
                        $_.EventUserSid

                    EventUser = `
                        $_.EventUser


                    BootSessionId = `
                        $_.BootSessionId

                    BootSessionActive = `
                        $_.BootSessionActive


                    SecondsSincePreviousEvent = `
                        $_.SecondsSincePreviousEvent

                    OccurrencesInCollection = `
                        $_.OccurrencesInCollection
                }
            }
    )
}


function ConvertTo-HalonIncidentExport {

    param (
        $IncidentWindows
    )


    return @(
        $IncidentWindows |
            ForEach-Object {

                $Incident = $_


                $ExportEvents = @(
                    $Incident.Events |
                        ForEach-Object {

                            [PSCustomObject]@{

                                OccurrenceTime = `
                                    ConvertTo-HalonDateString `
                                        -Value $_.OccurrenceTime


                                LoggedTime = `
                                    ConvertTo-HalonDateString `
                                        -Value $_.LoggedTime


                                MinutesFromIncident = `
                                    $_.MinutesFromIncident

                                IncidentPhase = `
                                    $_.IncidentPhase

                                Position = `
                                    $_.Position

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
                                    $_.LifecycleContext

                                EventSignature = `
                                    $_.EventSignature

                                OccurrencesInCollection = `
                                    $_.OccurrencesInCollection

                                OccurrencesInIncidentWindow = `
                                    $_.OccurrencesInIncidentWindow

                                AnchorType = `
                                    $_.AnchorType

                                Message = `
                                    $_.Message
                            }
                        }
                )

# ---------------------------------------------
# DIAGNOSTIC ARTIFACT EXPORT
# ---------------------------------------------

                $ExportDiagnosticArtifacts = @(
                    @($Incident.DiagnosticArtifacts) |
                        ForEach-Object {

                            $Artifact = $_


                            [PSCustomObject]@{

                                Relationship = `
                                    $Artifact.Relationship


                                ArtifactType = `
                                    $Artifact.ArtifactType

                                ArtifactPath = `
                                    $Artifact.ArtifactPath

                                ReportId = `
                                    $Artifact.ReportId

                                BugCheckRaw = `
                                    $Artifact.BugCheckRaw


                                EvidenceSource = `
                                    [PSCustomObject]@{

                                        RecordId = `
                                            $Artifact.EvidenceSource.RecordId

                                        EventID = `
                                            $Artifact.EvidenceSource.EventID

                                        Provider = `
                                            $Artifact.EvidenceSource.Provider

                                        OccurrenceTime = `
                                            ConvertTo-HalonDateString `
                                                -Value $Artifact.EvidenceSource.OccurrenceTime

                                        LoggedTime = `
                                            ConvertTo-HalonDateString `
                                                -Value $Artifact.EvidenceSource.LoggedTime
                                    }


                                IncidentAssociation = `
                                    [PSCustomObject]@{

                                        RecordId = `
                                            $Artifact.IncidentAssociation.RecordId

                                        EvidenceBasis = `
                                            $Artifact.IncidentAssociation.EvidenceBasis
                                    }


                                EvidenceBasis = `
                                    $Artifact.EvidenceBasis
                            }
                        }
                )

                [PSCustomObject]@{

                    IncidentType = `
                        $Incident.IncidentType


                   AnchorTime = `
                        ConvertTo-HalonDateString `
                            -Value $Incident.AnchorTime

                    WindowStart = `
                        ConvertTo-HalonDateString `
                            -Value $Incident.WindowStart

                    WindowEnd = `
                        ConvertTo-HalonDateString `
                            -Value $Incident.WindowEnd


                    EventCount = `
                        $Incident.EventCount


                    Events = `
                        $ExportEvents
                    
                    DiagnosticArtifactCount = `
                        @(
                            $ExportDiagnosticArtifacts
                        ).Count

                    DiagnosticArtifacts = `
                        $ExportDiagnosticArtifacts
                }
            }
    )
}

function ConvertTo-HalonProcessLineageExport {

    param (
        $ProcessLineages
    )


    return @(
        $ProcessLineages |
            ForEach-Object {

                $ProcessLineage = $_


                $ExportLineage = @(
                    $ProcessLineage.Lineage |
                        ForEach-Object {

                            [PSCustomObject]@{

                                Depth = `
                                    $_.Depth


                                ProcessTime = `
                                    ConvertTo-HalonDateString `
                                        -Value $_.ProcessTime


                                ProcessId = `
                                    $_.ProcessId

                                ProcessName = `
                                    $_.ProcessName

                                SecurityRecordId = `
                                    $_.SecurityRecordId


                                SubjectIdentity = `
                                    $_.SubjectIdentity

                                SubjectUserSid = `
                                    $_.SubjectUserSid

                                SubjectLogonId = `
                                    $_.SubjectLogonId


                                ParentProcessFound = `
                                    $_.ParentProcessFound

                                EvidenceBasisToParent = `
                                    $_.EvidenceBasisToParent
                            }
                        }
                )


                [PSCustomObject]@{

                    ProcessTime = `
                        ConvertTo-HalonDateString `
                            -Value $ProcessLineage.ProcessTime


                    ProcessId = `
                        $ProcessLineage.ProcessId

                    ProcessName = `
                        $ProcessLineage.ProcessName

                    ProcessSecurityRecordId = `
                        $ProcessLineage.ProcessSecurityRecordId


                    LineageNodeCount = `
                        $ProcessLineage.LineageNodeCount

                    AncestorCount = `
                        $ProcessLineage.AncestorCount


                    TerminationReason = `
                        $ProcessLineage.TerminationReason


                    Lineage = `
                        $ExportLineage
                }
            }
    )
}

function ConvertTo-HalonProcessExecutionContextExport {

    param (
        $ProcessExecutionContexts
    )

    $ExecutionContextExports = `
        [System.Collections.Generic.List[object]]::new()


    foreach (
        $ProcessExecutionContext in
        @($ProcessExecutionContexts)
    ) {

        $ContextLineageExports = `
            [System.Collections.Generic.List[object]]::new()


        foreach (
            $Node in
            @($ProcessExecutionContext.ContextLineage)
        ) {

            $WindowsSessionExports = `
                [System.Collections.Generic.List[object]]::new()


            foreach (
                $Session in
                @($Node.WindowsSessionMatches)
            ) {

                $WindowsSessionExports.Add(
                    [PSCustomObject]@{

                        User = `
                            $Session.User

                        SessionId = `
                            $Session.SessionId

                        SourceAddress = `
                            $Session.SourceAddress


                        SessionStart = `
                            ConvertTo-HalonDateString `
                                -Value $Session.SessionStart


                        SessionEnd = `
                            ConvertTo-HalonDateString `
                                -Value $Session.SessionEnd


                        State = `
                            $Session.State


                        LogonRecordId = `
                            $Session.LogonRecordId

                        LogoffRecordId = `
                            $Session.LogoffRecordId


                        SecondsFromSessionStartToProcess = `
                            $Session.SecondsFromSessionStartToProcess


                        SecondsFromSecurityLogonToSessionStart = `
                            $Session.SecondsFromSecurityLogonToSessionStart
                    }
                )
            }


            $ContextLineageExports.Add(
                [PSCustomObject]@{

                    Depth = `
                        $Node.Depth


                    ProcessTime = `
                        ConvertTo-HalonDateString `
                            -Value $Node.ProcessTime


                    ProcessId = `
                        $Node.ProcessId

                    ProcessName = `
                        $Node.ProcessName

                    SecurityRecordId = `
                        $Node.SecurityRecordId


                    SubjectIdentity = `
                        $Node.SubjectIdentity

                    SubjectUserSid = `
                        $Node.SubjectUserSid

                    SubjectLogonId = `
                        $Node.SubjectLogonId


                    SecurityLogonContextFound = `
                        $Node.SecurityLogonContextFound


                    SecurityLogonIdentity = `
                        $Node.SecurityLogonIdentity

                    SecurityLogonUserSid = `
                        $Node.SecurityLogonUserSid

                    SecurityLogonType = `
                        $Node.SecurityLogonType


                    SecurityLogonTime = `
                        ConvertTo-HalonDateString `
                            -Value $Node.SecurityLogonTime


                    SecurityLogonRecordId = `
                        $Node.SecurityLogonRecordId


                    SecurityLogonEvidenceBasis = `
                        $Node.SecurityLogonEvidenceBasis


                    WindowsSessionMatchCount = `
                        $Node.WindowsSessionMatchCount


                    WindowsSessionEvidenceBasis = `
                        $Node.WindowsSessionEvidenceBasis


                    WindowsSessionMatches = `
                        $WindowsSessionExports.ToArray()


                    ParentProcessFound = `
                        $Node.ParentProcessFound


                    EvidenceBasisToParent = `
                        $Node.EvidenceBasisToParent
                }
            )
        }


        $ExecutionContextExports.Add(
            [PSCustomObject]@{

                ProcessTime = `
                    ConvertTo-HalonDateString `
                        -Value $ProcessExecutionContext.ProcessTime


                ProcessId = `
                    $ProcessExecutionContext.ProcessId

                ProcessName = `
                    $ProcessExecutionContext.ProcessName

                ProcessSecurityRecordId = `
                    $ProcessExecutionContext.ProcessSecurityRecordId


                LineageNodeCount = `
                    $ProcessExecutionContext.LineageNodeCount

                AncestorCount = `
                    $ProcessExecutionContext.AncestorCount


                TerminationReason = `
                    $ProcessExecutionContext.TerminationReason


                ContextLineage = `
                    $ContextLineageExports.ToArray()
            }
        )
    }


    return $ExecutionContextExports.ToArray()
}