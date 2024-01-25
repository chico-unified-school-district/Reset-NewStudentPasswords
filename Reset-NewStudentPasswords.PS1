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
 # [ValidateScript( { Test-Connection -ComputerName $_ -Quiet -Count 1 })]
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

function Add-ToGroup {
 process {
  if ($null -eq $_.group) { return $_ }
  Write-Host ('{0},{1},{2},{3}' -f $MyInvocation.MyCommand.Name, $_.samid, $_.grade , $_.group)
  $addParams = @{
   Identity = $_.group
   Members  = $_.guid
   # ErrorAction = 'SilentlyContinue'
   Confirm  = $false
   WhatIf   = $WhatIf
  }
  Add-ADGroupMember @addParams
  $_
 }
}

function Complete-Processing {
 process {
  Write-Verbose ($MyInvocation.MyCommand.Name, $_ | Out-String)
 }
}

function Format-Obj ($group) {
 process {
  Write-Verbose ($MyInvocation.MyCommand.Name, $_ | Out-String)
  [PSCustomObject]@{
   id        = $_.EmployeeID
   gmail     = $_.HomePage
   samid     = $_.SamAccountName
   grade     = $_.Gecos
   guid      = $_.ObjectGUID
   tempPw    = $null
   group     = if ([int]$_.Gecos -ge 6) { $group } else { $null }
   suspended = $null
  }
 }
}

function Get-GSuiteData {
 begin {
  Write-Verbose ('{0},Getting recent student accounts' -f $MyInvocation.MyCommand.Name)
  ( $gusers = & $gam print users query "orgUnitPath:/STUDENTS" fields suspended, creationTime ) *>$null
  $gobjs = $gusers | ConvertFrom-Csv | Where-Object { (Get-Date $_.creationTime) -gt ((Get-Date).AddDays(-5)) }
 }
 process {
  $msg = $MyInvocation.MyCommand.Name, $_.samid
  Write-Verbose ('{0},{1}' -f $msg)
  $gmail = $_.gmail
  $guser = $gobjs.Where({ $_.primaryEmail -eq $gmail })
  # Write-Verbose ($guser | Out-String)
  if ($null -eq $guser) { return (Write-Host ("{0},{1},Gsuite not synced " -f $msg)) }
  $_.suspended = $guser.suspended
  $_
 }
}

function Get-UserObjs ($base) {
 begin {
  $cutOff = (Get-Date).AddDays(-5)
  $params = @{
   Filter     = "(Created -ge `'$cutOff`') -and
                 (employeeID -like '*') -and
                 (homepage -like '*@*') -and
                 (Enabled -eq 'True')"
   Properties = 'HomePage', 'EmployeeID', 'Created', 'PasswordLastSet', 'LastLogonDate', 'Gecos'
   SearchBase = $base
  }
 }
 process {
  $objs = Get-ADUser @params | Where-Object {
   (($_.created.DateTime -eq $_.passwordlastset.DateTime) -or ($null -eq $_.passwordlastset.DateTime)) -and
   ($null -eq $_.LastLogonDate)
  }
  if ($objs) { Write-Host ('{0},Count: {1}' -f $MyInvocation.MyCommand.Name, $objs.count) }
  $objs | Sort-Object -Property Gecos
 }
}

function Remove-FromGroup {
 process {
  if ($null -eq $_.group) { return $_ }
  Write-Host ('{0},{1},{2},{3}' -f $MyInvocation.MyCommand.Name, $_.samid, $_.grade , $_.group)
  $removeParams = @{
   Identity = $_.group
   Members  = $_.guid
   # ErrorAction = 'SilentlyContinue'
   Confirm  = $false
   WhatIf   = $WhatIf
  }
  if (!$WhatIf) { Write-Debug 'Reset PW?' }
  Remove-ADGroupMember @removeParams
  if (!$WhatIf) { Start-Sleep 10 } # Give AD time to replicate
  $_
 }
}

function Reset-Password {
 process {
  Write-Host ('{0},{1}' -f $MyInvocation.MyCommand.Name, $_.samid)
  $setPwParams = @{
   Identity    = $_.guid
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

function Set-GSuiteActive {
 process {
  if ($_.suspended -eq 'false') { return $_ }
  $msg = $MyInvocation.MyCommand.Name, "& $gam update user $($_.gmail) suspended off"
  Write-Host ('{0},{1}' -f $msg)
  if (!$WhatIf) { & $gam update user $_.gamil suspended off *>$null }
  $_
 }
}

function Set-PwData ($params, $query) {
 process {
  $msg = $MyInvocation.MyCommand.Name, $_.samid
  $cleanId = Format-SqlVar $_.id
  $sql = $query -f $cleanId
  Write-Verbose ($sql | Out-string)
  $data = Invoke-SqlCmd @params -Query $sql | ConvertTo-Csv | ConvertFrom-Csv
  if ($null -eq $data) { return (Write-Host ('{0},{1},Sql Data not found.' -f $msg)) }
  $tempPw = try { [string](Get-Date $data.tempPw -Format yyMMdd) }
  catch { return (Write-Host ('{0},{1},tempPW error' -f $msg)) }
  # if ($null -eq $data.tempPw) { return (Write-Host ('{0},{1},NO DATA' -f $msg) ) }
  $securePw = ConvertTo-SecureString -String $tempPw -AsPlainText -Force
  Write-verbose ('{0},{1}' -f $msg)
  $_.tempPw = $securePw
  $_
 }
}

# ===================================== Main ====================================
# Imported Functions
. .\lib\Clear-SessionData.ps1
. .\lib\Add-Module.ps1
. .\lib\Format-SqlVar.ps1
. .\lib\New-ADSession.ps1
. .\lib\Select-DomainController.ps1
. .\lib\Show-TestRun.ps1

Show-TestRun

$gam = '.\bin\gam.exe' # GSuite cmd line tool - oauth2.txt is copied before this script runs

'SQLServer' | Add-Module
$sqlParams = @{
 Server                 = $SQLServer
 Database               = $SQLDatabase
 Credential             = $SQLCredential
 TrustServerCertificate = $true
 Debug                  = $false
}

'Runs every {0} minutes. Stops at {1}' -f ($LoopDelaySeconds / 60), $StopTime
do {
 Clear-SessionData
 $dc = Select-DomainController $DomainControllers
 $cmdLets = 'Get-ADUser', 'Set-ADUser', 'Set-ADAccountPassword',
 'Add-ADGroupMember', 'Remove-ADGroupMember'
 New-ADSession -dc $dc -cmdlets $cmdLets -cred $ADCredential
 Get-UserObjs $ADSearchBase |
 Format-Obj $SecondaryGroup |
 Set-PwData $sqlParams $TempPWQuery |
 Get-GSuiteData |
 Remove-FromGroup |
 Reset-Password |
 Add-ToGroup |
 Set-GSuiteActive |
 Complete-Processing
 if (!$WhatIf) { Start-Sleep $LoopDelaySeconds }
} until ($WhatIf -or ((Get-Date) -ge (Get-Date $StopTime)))