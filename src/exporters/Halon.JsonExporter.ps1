# ---------------------------------------------
# HALON JSON EXPORTERS
# ---------------------------------------------


function Write-HalonJsonArray {

    param (
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [int]$Depth = 6
    )


    # -----------------------------------------
    # NORMALIZE COLLECTION
    # -----------------------------------------
    #
    # HALON collection artifact contract:
    #
    # Zero records -> []
    # One record   -> [{ ... }]
    # Many records -> [{ ... }, { ... }]
    #
    # Null is treated as zero evidence records,
    # not as an evidence record containing null.

    $Items = @()


    if ($null -ne $InputObject) {

        $Items = @(
            $InputObject |
                Where-Object {
                    $null -ne $_
                }
        )
    }


    # -----------------------------------------
    # SERIALIZE
    # -----------------------------------------

    if ($Items.Count -eq 0) {

        $Json = "[]"

    }
    else {

        $Json = ConvertTo-Json `
            -InputObject $Items `
            -Depth $Depth
    }


    # -----------------------------------------
    # WRITE ARTIFACT
    # -----------------------------------------

    Set-Content `
        -Path $Path `
        -Value $Json `
        -Encoding UTF8
}