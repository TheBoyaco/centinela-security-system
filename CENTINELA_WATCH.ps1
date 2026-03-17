# CENTINELA_WATCH.ps1 — ELITE v2 (SOLO LECTURA + LOG)
# NO bloquea, NO mata procesos, NO toca firewall, NO toca tu bot trading.

$excludeProc = @('python3.13','python','powershell')

# Lista blanca de procesos normales (ajustable)
$allowProc = @(
  'chrome','msedgewebview2','steam','steamwebhelper',
  'EADesktop','EABackgroundService','EACefSubProcess',
  'ManyCam','RiotClientServices',
  'asus_framework','ArmourySocketServer','LightingService','ROGLiveService',
  'ArmouryCrate.UserSessionHelper','AppleMobileDeviceService','mDNSResponder',
  'AacAmbientLighting','svchost',
  'Widgets','DuckDuckGo'
)

# Puertos comunes (no alertar)
$commonPorts = @(443,80,5228,5222)

$logPath = "C:\Centinela\logs"
$logFile = Join-Path $logPath ("watch_" + (Get-Date -Format "yyyyMMdd") + ".log")
New-Item -ItemType Directory -Path $logPath -Force | Out-Null

$seen = @{}

function Is-PrivateIP($ip){
  return ($ip -match '^(127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')
}

function Is-SuspiciousPath($path){
  if (-not $path) { return $true }

  # Excepción: OneDrive legítimo suele vivir en AppData\Local\Microsoft\OneDrive
  if ($path -match '\\Microsoft\\OneDrive\\OneDrive\.exe$') { return $false }

  return ($path -match '\\AppData\\|\\Temp\\|\\Downloads\\|\\Desktop\\|\\ProgramData\\')
}

function LogLine($text){
  $text | Out-File -FilePath $logFile -Append -Encoding UTF8
}

LogLine "===== CENTINELA WATCH ELITE v2 START $(Get-Date) ====="

while ($true) {
  $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -and -not (Is-PrivateIP $_.RemoteAddress) }

  foreach ($c in $conns) {
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    if (-not $p) { continue }
    if ($excludeProc -contains $p.ProcessName) { continue }

    $path = $p.Path
    $proc = $p.ProcessName
    $rport = [int]$c.RemotePort

    $isWhitelisted = $allowProc -contains $proc
    $isCommonPort  = $commonPorts -contains $rport
    $isBadPath     = Is-SuspiciousPath $path

    # NUEVA regla v2:
    # - Si el proceso está en whitelist y path NO es sospechoso -> NO alertar por puerto raro
    # - Solo alertar por puerto raro si el proceso NO está whitelisted
    $portIsSuspicious = (-not $isCommonPort) -and (-not $isWhitelisted)

    # Alertar si:
    # 1) Proceso NO está whitelisted, o
    # 2) Path sospechoso, o
    # 3) Puerto raro y proceso NO whitelisted
    if ((-not $isWhitelisted) -or $isBadPath -or $portIsSuspicious) {

      $key = "{0}|{1}|{2}" -f $proc,$c.RemoteAddress,$c.RemotePort
      if (-not $seen.ContainsKey($key)) {
        $seen[$key] = Get-Date

        $reason = @()
        if (-not $isWhitelisted) { $reason += "PROC_NO_WHITELIST" }
        if ($isBadPath)          { $reason += "PATH_SOSPECHOSO" }
        if ($portIsSuspicious)   { $reason += "PUERTO_RARO" }

        $line = "[ALERTA_ELITE] {0}  REASON={1}  PROC={2}  PID={3}  -> {4}:{5}  (Local:{6})  PATH={7}" -f (Get-Date), ($reason -join ","), $proc, $c.OwningProcess, $c.RemoteAddress, $c.RemotePort, $c.LocalPort, $path
        LogLine $line
        [console]::beep(1000,90)
      }
    }
  }

  Start-Sleep -Seconds 5
}
