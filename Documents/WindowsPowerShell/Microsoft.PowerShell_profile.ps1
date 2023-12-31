if ($host.Name -eq 'ConsoleHost')
{
    Import-Module PSReadLine
}

Import-Module posh-git
Import-Module oh-my-posh
Set-PoshPrompt -Theme ~/.Fairyfloss.omp.json

if($host.name -eq 'ConsoleHost')
{
Import-Module PSReadLine
}

# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}

