param(
    [string]$Version
)

$root = $PSScriptRoot + '\..'

$readme = Get-Content -Path "$root\README.md" | ForEach-Object -Process {if ($_ -match '^# dync \d+\.\d+\.\d+  $') {"# dync $Version  "} else {$_}}
Set-Content -Path "$root\README.md" -Value $readme
