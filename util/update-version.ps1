param(
    [string]$Version
)

$root = $PSScriptRoot + '\..'

$readme = Get-Content -Path "$root\README.md" | ForEach-Object -Process {if ($_ -match '^# dync \d+\.\d+\.\d+  $') {"# dync $Version  "} else {$_}}
Set-Content -Path "$root\README.md" -Value $readme

$dync = ((Get-Content -Path "$root\src\dync.py") -join  "`n") -replace ("(class dyncBase\(ABC\):\s+NAME\s*=\s*'dync'\s+VERSION\s*=\s*)'\d+\.\d+\.\d+'", ('$1''' + $Version + ''''))
Set-Content -Path "$root\src\dync.py" -Value $dync
