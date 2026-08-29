# ---------------------------------------------
# HALON SUMMARY BUILDERS
# ---------------------------------------------


function Get-HalonEvidenceSummary {

    param (
        $Events
    )


    Write-Host "Categorizing incident evidence..."


    return @(
        $Events |
            Group-Object Category |
            Sort-Object Count -Descending |
            ForEach-Object {

                [PSCustomObject]@{

                    Category = `
                        $_.Name

                    Count = `
                        $_.Count
                }
            }
    )
}


function Get-HalonEventSummary {

    param (
        $Events
    )


    Write-Host "Grouping recurring events..."


    return @(
        $Events |
            Group-Object Provider, EventID, Level |
            Sort-Object Count -Descending |
            ForEach-Object {

                [PSCustomObject]@{

                    Count = `
                        $_.Count

                    Provider = `
                        $_.Group[0].Provider

                    EventID = `
                        $_.Group[0].EventID

                    Level = `
                        $_.Group[0].Level
                }
            }
    )
}