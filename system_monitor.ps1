$interval = 1

Clear-Host
Write-Host "Starter real-time system monitor (CTRL + C for at stoppe)...`n"

while ($true) {
    # Hent CPU %
    $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue

    # Hent RAM info
    $ramTotal = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    $ramFree  = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB
    $ramUsed  = $ramTotal - $ramFree

  
    Clear-Host
    Write-Host "=== LIVE SYSTEM MONITOR ==="
    Write-Host "Tid: $(Get-Date -Format 'HH:mm:ss')"
    Write-Host ""
    Write-Host "CPU-forbrug: $([math]::Round($cpu, 2)) %"
    Write-Host "RAM total:   $([math]::Round($ramTotal, 2)) GB"
    Write-Host "RAM brugt:   $([math]::Round($ramUsed, 2)) GB"
    Write-Host "RAM fri:     $([math]::Round($ramFree, 2)) GB"
    Write-Host ""
    Write-Host "Tryk CTRL+C for at stoppe..."

    Start-Sleep -Seconds $interval
}
