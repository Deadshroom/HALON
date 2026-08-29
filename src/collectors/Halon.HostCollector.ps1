# ---------------------------------------------
# HALON HOST EVIDENCE COLLECTORS
# ---------------------------------------------


function Get-HalonSystemInformation {

    param (
        [string]$ComputerName
    )

    Write-Host "Collecting system information..."

    $OS = Get-CimInstance Win32_OperatingSystem
    $Computer = Get-CimInstance Win32_ComputerSystem
    $CPU = Get-CimInstance Win32_Processor


    return [PSCustomObject]@{

        ComputerName = $ComputerName

        Manufacturer = $Computer.Manufacturer
        Model        = $Computer.Model

        OS        = $OS.Caption
        OSVersion = $OS.Version
        OSBuild   = $OS.BuildNumber

        LastBootTime = $OS.LastBootUpTime

        CPU = $CPU.Name

        RAMGB = [math]::Round(
            $Computer.TotalPhysicalMemory / 1GB,
            2
        )

        Administrator = Test-IsAdministrator
    }
}


function Get-HalonDiskInformation {

    Write-Host "Collecting disk information..."

    return @(
        Get-CimInstance Win32_LogicalDisk |
            Select-Object `
                DeviceID,
                VolumeName,
                FileSystem,
                DriveType,
                @{
                    Name = "SizeGB"
                    Expression = {
                        [math]::Round(
                            $_.Size / 1GB,
                            2
                        )
                    }
                },
                @{
                    Name = "FreeGB"
                    Expression = {
                        [math]::Round(
                            $_.FreeSpace / 1GB,
                            2
                        )
                    }
                }
    )
}


function Get-HalonServiceInformation {

    Write-Host "Collecting service information..."

    return @(
        Get-Service |
            Select-Object `
                Name,
                DisplayName,
                Status,
                StartType
    )
}