<#
.SYNOPSIS
Resets Gsuite passwords for non-staff
.DESCRIPTION
Using gam.exe, an encrypted oauth2.txt file, a Domain Controller,
and an AD Account with propers access to the Domain,
the script can update AD/GSuite passwords and GSuite attributes for
qualifying AD user objects.
.EXAMPLE
Reset-GSuitePasswords.ps1 -DC servername -ADCred $adCredObject -SQLServer someSQLserver -SQLdatabase someDatabase -$TempPWQuery someSQLquery -SecondaryGroup SomeADGroup
.EXAMPLE
Reset-GSuitePasswords.ps1 -DC servername -ADCred $adCredObject -SQLServer someSQLserver -SQLdatabase someDatabase -$TempPWQuery someSQLquery -SecondaryGroup SomeADGroup-WhatIf -Verbose -Debug
.EXAMPLE
Reset-GSuitePasswords.ps1 -OneLoop -DC servername -SQLServer someSQLserver -SQLdatabase someDatabase -$TempPWQuery someSQLquery -SecondaryGroup SomeADGroup-ADCred $adCredObject
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
 [Alias('DCs')]
 [string[]]$DomainControllers,
 [Parameter(Mandatory = $True)]
 [System.Management.Automation.PSCredential]$ADCredential,
 [Parameter(Mandatory = $True)]
 [string]$ADSearchBase,
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

function Get-ADData ($OrgUnit, $props) {
 $cutOff = (Get-Date).AddDays(-5)
 $params = @{
  Filter     = "(Created -ge '$cutOff') -and (employeeID -like '*')"
  Properties = $props
  SearchBase = $OrgUnit
 }
 $objs = Get-ADUser @params | Where-Object {
  (($_.created.DateTime -eq $_.passwordlastset.DateTime) -or ($null -eq $_.passwordlastset.DateTime)) -and
  ($null -eq $_.LastLogonDate)
 }
 Write-Host ('{0},Count: {1}' -f $MyInvocation.MyCommand.Name, @($objs).count) -F Green
 $objs
}

function Reset-Password {
 process {
  Write-Host ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName) -F Blue
  $setPwParams = @{
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
  if (!$WhatIf) { & $gam update user $_.gamil suspended off *>$null }
  $_
 }
}

function Set-GsuiteData {
 process {
  Write-Verbose ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.HomePage)
  ($_.gsuite = & $gam print users query "email:$($_.ad.HomePage)" allfields | ConvertFrom-Csv)*>$null
  if (!$_.gsuite) { return } # Skip if gsuite data missing
  $_
 }
}

function Set-MissingTempGrade {
 process {
  if ($_.ad.gecos -match '\d') { return $_ } # make sure grade/gecos is an integer
  # set grade (gecos) to 0 for elementary and set it to 100 for non-elementary
  $_.grade = if ($_.ad.Department -match 'Elementary') { 0 } else { 100 }
  Write-Host ('{0},{1},{2}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName, $_.grade) -F Magenta
  Set-ADUser -Identity $_.ad.ObjectGUID -Add @{gecos = $_.grade } -WhatIf:$WhatIf
  $_
 }
}

function Set-PwData ($params, $query) {
 process {
  $data = New-SqlOperation @params -Query $query -Parameters "id=$($_.ad.EmployeeID)" | ConvertTo-Csv | ConvertFrom-Csv
  if (!$data -or ($data.tempPw -notmatch '\d{6}')) { return }
  Write-verbose ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName)
  $securePw = ConvertTo-SecureString -String $data.tempPw -AsPlainText -Force
  $_.tempPw = $securePw
  $_
 }
}

function Update-GroupAdd {
 process {
  if (!$_.group) { return $_ }
  Write-Host ('{0},{1},{2}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName, $_.group) -F DarkMagenta
  Add-ADGroupMember  -Identity $_.group -Members $_.ad.ObjectGUID -Confirm:$false -WhatIf:$WhatIf
  $_
 }
}

function Update-GroupRemove {
 process {
  if (!$_.group) { return $_ }
  Write-Host ('{0},{1},{2}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName , $_.group) -F Magenta
  Remove-ADGroupMember -Identity $_.group -Members $_.ad.ObjectGUID -Confirm:$false -WhatIf:$WhatIf
  $_
 }
}

function Wait-GroupRemoval {
 begin { $maxWait = 120 }
 process {
  if (!$_.group) { return $_ }
  Write-Verbose ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.ad.SamAccountName)
  do { Start-Sleep 3; $maxWait -= 3 }
  until (
   ((Get-ADUser -Identity $_.ad.ObjectGUID -Properties memberof | select-object memberof) -notcontains $_.group) -or
   ($maxWait -le 0) -or
   ($WhatIf)
  )
  $_
 }
}

# ========================================================================
Import-Module -Name 'dbatools', 'CommonScriptFunctions'
Show-BlockInfo Start
if ($WhatIf) { Show-TestRun }

$gam = '.\bin\gam.exe' # GSuite cmd line tool - oauth2.txt is copied before this script runs

$sqlParams = @{
 Server     = $SQLServer
 Database   = $SQLDatabase
 Credential = $SQLCredential
}

$adCmdLets = 'Get-ADUser', 'Set-ADUser', 'Set-ADAccountPassword',
'Add-ADGroupMember', 'Remove-ADGroupMember'
$adProperties = 'HomePage', 'EmployeeID', 'Created', 'PasswordLastSet',
'LastLogonDate', 'Gecos', 'Department', 'memberof'

'Runs every {0} minutes. Stops at {1}' -f ($LoopDelaySeconds / 60), $StopTime
do {
 Clear-SessionData

 Connect-ADSession -DomainControllers $DomainControllers -Credential $ADCredential -Cmdlets $adCmdLets

 Get-ADData $ADSearchBase $adProperties |
  Format-Obj |
   Set-GSuiteData |
    Set-Group $SecondaryGroup |
     Set-MissingTempGrade |
      Set-PwData $sqlParams $TempPWQuery |
       Update-GroupRemove |
        Wait-GroupRemoval |
         Reset-Password |
          Update-GroupAdd |
           Set-GSuiteActive |
            Complete-Processing

 Clear-SessionData
 if (!$WhatIf) { Start-Sleep $LoopDelaySeconds }
} until ($WhatIf -or ((Get-Date) -ge (Get-Date $StopTime)))
if ($WhatIf) { Show-TestRun }
Show-BlockInfo End
