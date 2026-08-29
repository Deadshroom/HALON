# ---------------------------------------------
# HALON RUN MANIFEST BUILDER
# ---------------------------------------------


function New-HalonRunManifest {

    param (
        [string]$ComputerName,

        [datetime]$CollectionStart,

        [string]$OutputDirectory,

        $Events,

        $IdentityCollection,

        $WindowsSessionCollection,

        $ProcessAuditCapability,

        $ProcessCollection,

        $ProcessCreationEvents,

        [string]$Version = "0.1"
    )


    return [PSCustomObject]@{

        Tool = `
            "HALON"

        Version = `
            $Version


        ComputerName = `
            $ComputerName


        CollectionStart = `
            $CollectionStart

        CollectionEnd = `
            Get-Date


        EventsCollected = @(
            $Events
        ).Count


        OutputDirectory = `
            $OutputDirectory


        TimeZone = `
            (Get-TimeZone).Id


        IdentityCollectionStatus = `
            $IdentityCollection.Status

        IdentityCollectionError = `
            $IdentityCollection.Error


        WindowsSessionCollectionStatus = `
            $WindowsSessionCollection.Status

        WindowsSessionCollectionError = `
            $WindowsSessionCollection.Error


        ProcessCreationAuditPolicy = `
            $ProcessAuditCapability.CurrentAuditPolicy

        ProcessCreationAuditEnabled = `
            $ProcessAuditCapability.SuccessAuditingEnabled


        ProcessCreationEvidenceStatus = `
            $ProcessCollection.Status

        ProcessCreationEventsCollected = @(
            $ProcessCreationEvents
        ).Count
    }
}