<#
.SYNOPSIS
Resets Gsuite passwords for non-staff
.DESCRIPTION
Using gam.exe, an encrypted oauth2.txt file, a Domain Controller,
and an AD Account with propers access to the Domain,
the script can update AD/GSuite passwords and GSuite attributes for
qualifying AD user objects.
.EXAMPLE
Reset-GSuitePasswords.ps1 -ADCred $adCredObject -SQLServer someSQLserver -SQLdatabase someDatabase -$TempPWQuery someSQLquery -SecondaryGroup SomeADGroup
.EXAMPLE
Reset-GSuitePasswords.ps1 -ADCred $adCredObject -SQLServer someSQLserver -SQLdatabase someDatabase -$TempPWQuery someSQLquery -SecondaryGroup SomeADGroup-WhatIf -Verbose -Debug
.EXAMPLE
Reset-GSuitePasswords.ps1 -OneLoop -SQLServer someSQLserver -SQLdatabase someDatabase -$TempPWQuery someSQLquery -SecondaryGroup SomeADGroup-ADCred $adCredObject
.INPUTS
Gam.exe oauth2.txt
ACtive Driectory Domain Controller name.
Active Directory account with access to the Domain Controller
and proper OU access
.OUTPUTS
AD objects are updated
AD/GSuite passwords are updated
GSuite attributes are updated
Logging info is generated for each action
.NOTES
This was built for use with Jenkins
#>
[cmdletbinding()]
param (
 [Parameter(Mandatory = $True)]
 [System.Management.Automation.PSCredential]$ADCredential,
 [Parameter(Mandatory = $True)]
 [string]$SQLServer,
 [Parameter(Mandatory = $True)]
 [string]$SQLDatabase,
 [Parameter(Mandatory = $True)]
 [System.Management.Automation.PSCredential]$SQLCredential,
 [Parameter(Mandatory = $True)]
 [string]$TempPWQuery,
 [Parameter(Mandatory = $True)]
 [string]$SecondaryGroup,
 [string]$StopTime = '6:00pm',
 # Delay between each iteration.
 [int]$LoopDelaySeconds = 900,
 [Alias('wi')]
 [switch]$WhatIf
)

function Complete-Processing {
 process {
  Write-Verbose ($MyInvocation.MyCommand.Name, $_ | Out-String)
 }
}

function Format-Obj {
 process {
  [PSCustomObject]@{
   ad     = $_
   gsuite = $null
   tempPw = $null
   group  = $null
   grade  = $null
  }
 }
}

function Get-ADData ($props, [pscredential]$cred) {
 $cutOff = (Get-Date).AddDays(-5)
 $params = @{
  Credential = $cred
  Filter     = "Created -ge '$cutOff' -and employeeID -like '*' -and employeeType -eq 'student'"
  Properties = $props
 }
 $objs = Get-ADUser @params | Where-Object {
  (($_.created.DateTime -eq $_.PasswordLastSet.DateTime) -or ($null -eq $_.PasswordLastSet.DateTime)) -and
  ($null -eq $_.LastLogonDate)
 }
 Write-Verbose ('{0},Count: {1}' -f $MyInvocation.MyCommand.Name, @($objs).count)
 $objs
}

function Reset-Password {
 param([pscredential]$cred)
 process {
  Write-Host ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName) -F Blue
  $setPwParams = @{
   Credential  = $cred
   Identity    = $_.ad.ObjectGUID
   NewPassword = $_.tempPw
   Reset       = $True
   Confirm     = $False
   WhatIf      = $WhatIf
   ErrorAction = 'Stop'
  }
  Set-ADAccountPassword @setPwParams
  $_
 }
}

function Set-Group ($group) {
 process {
  $_.group = if ($_.ad.memberof -match $group) { $group }
  $_
 }
}

function Set-GSuiteActive {
 process {
  if ($_.gsuite.suspended -eq 'False') { return $_ }
  Write-Host ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName)
  if (!$WhatIf) {
   $ErrorActionPreference = 'Continue'
   & $gam update user $_.gamil suspended off *>$null
   $ErrorActionPreference = 'Stop'
  }
  $_
 }
}

function Set-GSuiteData {
 process {
  Write-Verbose ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.HomePage)
  $ErrorActionPreference = 'Continue'
  ($_.gsuite = & $gam print users query "email:$($_.ad.HomePage)" allfields | ConvertFrom-Csv)*>$null
  $ErrorActionPreference = 'Stop'
  if (!$_.gsuite) { return } # Skip if gsuite data missing
  $_
 }
}

function Set-MissingTempGrade ([pscredential]$cred) {
 process {
  if ($_.ad.gecos -match '\d') { return $_ } # make sure grade/gecos is an integer
  # set grade (gecos) to 0 for elementary and set it to 100 for non-elementary
  $_.grade = if ($_.ad.Department -match 'Elementary') { 0 } else { 100 }
  $params = @{
   Identity   = $_.ad.ObjectGUID
   Replace    = @{gecos = $_.grade }
   Credential = $cred
   WhatIf     = $WhatIf
  }
  Write-Host ('{0},{1},{2}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName, $_.grade) -F Magenta
  Set-ADUser @params
  $_
 }
}

function Set-PwData ($params, $query) {
 process {
  $data = New-SqlOperation @params -Query $query -Parameters "id=$($_.ad.EmployeeID)" | ConvertTo-Csv | ConvertFrom-Csv
  if (!$data -or ($data.tempPw -notmatch '\d{6}')) { return }
  Write-Verbose ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName)
  $securePw = ConvertTo-SecureString -String $data.tempPw -AsPlainText -Force
  $_.tempPw = $securePw
  $_
 }
}

function Update-GroupAdd {
 param([pscredential]$cred)
 process {
  if (!$_.group) { return $_ }
  Write-Host ('{0},{1},{2}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName, $_.group) -F DarkMagenta
  Add-ADGroupMember -Credential $cred -Identity $_.group -Members $_.ad.ObjectGUID -Confirm:$false -WhatIf:$WhatIf
  $_
 }
}

function Update-GroupRemove {
 param([pscredential]$cred)
 process {
  if (!$_.group) { return $_ }
  Write-Host ('{0},{1},{2}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName , $_.group) -F Magenta
  Remove-ADGroupMember -Credential $cred -Identity $_.group -Members $_.ad.ObjectGUID -Confirm:$false -WhatIf:$WhatIf
  $_
 }
}

function Wait-GroupRemoval {
 param([pscredential]$cred)
 begin { $maxWait = 120 }
 process {
  if (!$_.group) { return $_ }
  Write-Verbose ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName)
  do { Start-Sleep 3; $maxWait -= 3 }
  until (
   ((Get-ADUser -Credential $cred -Identity $_.ad.ObjectGUID -Properties memberof | Select-Object memberof) -notcontains $_.group) -or
   ($maxWait -le 0) -or
   ($WhatIf)
  )
  $_
 }
}

# ========================================================================
Show-BlockInfo Start
Import-Module -Name 'dbatools', 'CommonScriptFunctions'
$cmdlet = 'Get-ADUser', 'Set-ADUser', 'Set-ADAccountPassword', 'Add-ADGroupMember', 'Remove-ADGroupMember'
Import-Module -Name ActiveDirectory -Cmdlet $cmdlet -WarningAction SilentlyContinue -ErrorAction Stop
Show-BlockInfo main
if ($WhatIf) { Show-TestRun }

$gam = 'C:\GAM7\gam.exe'

$sqlInstance = Connect-DbaInstance -SqlInstance $SQLServer -Database $SQLDatabase -SqlCredential $SQLCredential

$adProperties = 'HomePage', 'EmployeeID', 'Created', 'PasswordLastSet',
'LastLogonDate', 'Gecos', 'Department', 'MemberOf'

if (!$WhatIf) { 'Runs every {0} minutes. Stops at {1}' -f ($LoopDelaySeconds / 60), $StopTime }
do {
 Get-ADData -props $adProperties -cred $ADCredential |
  Format-Obj |
   Set-GSuiteData |
    Set-Group -group $SecondaryGroup |
     Set-MissingTempGrade -cred $ADCredential |
      Set-PwData $sqlInstance $TempPWQuery |
       Update-GroupRemove -cred $ADCredential |
        Wait-GroupRemoval -cred $ADCredential |
         Reset-Password -cred $ADCredential |
          Update-GroupAdd -cred $ADCredential |
           Set-GSuiteActive |
            Complete-Processing
 if ($WhatIf) { break }
 Start-Sleep $LoopDelaySeconds
} until ((Get-Date) -ge (Get-Date $StopTime))
if ($WhatIf) { Show-TestRun }
Show-BlockInfo End
