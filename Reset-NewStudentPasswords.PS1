<# 
.SYNOPSIS
 Resets Gsuite passwords for non-staff
.DESCRIPTION
Using gam.exe, an encrypted oauth2.txt file, a Domain Controller, 
and an AD Account with propers access to the Domain, 
the script can update AD/GSuite passwords and GSuite attributes for 
qualifying AD user objects.
.EXAMPLE
 Reset-GSuitePasswords.ps1 -DC servername -ADCred $adCredObject
.EXAMPLE
 Reset-GSuitePasswords.ps1 -DC servername -ADCred $adCredObject -WhatIf -Verbose -Debug
.EXAMPLE
 Reset-GSuitePasswords.ps1 -OneLoop -DC servername -ADCred $adCredObject
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
    [Alias('DC', 'Server')]
    [ValidateScript( { Test-Connection -ComputerName $_ -Quiet -Count 1 })]
    [string]$DomainController,
    # PSSession to Domain Controller and Use Active Directory CMDLETS  
    [Parameter(Mandatory = $True)]
    [Alias('ADCred')]
    [System.Management.Automation.PSCredential]$ADCredential,
    [Parameter(Mandatory = $True)]
    [string]$ADSearchBase,
    [Parameter(Mandatory = $True)]
    [ValidateScript( { Test-Connection -ComputerName $_ -Quiet -Count 1 })]
    [string]$SQLServer,
    [Parameter(Mandatory = $True)]
    [string]$SQLDatabase,
    [Parameter(Mandatory = $True)]
    [System.Management.Automation.PSCredential]$SQLCredential,
    [Parameter(Mandatory = $True)]
    [string]$TempPWQuery,
    [switch]$WhatIf
)

Clear-Host; $error.clear()
# Imported Sessions
# AD Domain Controller Session
$adCmdLets = 'Get-ADUser', 'Set-ADUser', 'Set-ADAccountPassword'
$adSession = New-PSSession -ComputerName $DomainController -Credential $ADCredential
Import-PSSession -Session $adSession -Module ActiveDirectory -CommandName $adCmdLets -AllowClobber > $null

# Variables

# Imported Functions
. .\lib\Add-Log.ps1 # Formats strings for logging purposes
. .\lib\Invoke-SqlCommand.ps1

# External Apps
$gam = '.\lib\gam-64\gam.exe' # GSuite cmd line tool - oauth2.txt is copied before this script runs

# Processing
$params = @{
    Filter     = {
        (employeeID -like "*") -and
        (homepage -like "*@ChicoUSD.net") -and
        (Enabled -eq $True)
    }
    Properties = 
    'employeeID',
    'homepage',
    'PasswordLastSet',
    'LastLogonDate',
    'Created'
    SearchBase = $ADSearchBase
}

if ( $WhatIf ) { $endTime = Get-Date } # DO Loop cut short on test run
else { $endTime = (get-date "5:00 PM") } # DO Loop stops at this time
if ($WhatIf) { $waitTime = 1 } else { $waitTime = 3600 } # Sleep fox x seconds between each loop.
Add-Log script "Running until $endTime" $WhatIf
if (!$WhatIf) { Add-Log script "Running every $($waitTime/60) minutes" }

do {
    Write-Verbose 'Getting qualifying AD Objects...'
    $userObjs = Get-ADUser @params | Where-Object {
        ($_.created -ge (Get-Date).AddDays(-200)) -and
        ($_.created.DateTime -eq $_.passwordlastset.DateTime) -and 
        ($null -eq $_.LastLogonDate)
    }

    foreach ( $user in $userObjs ) {
        # Get student info
        # Process AD Results
        $samid = $user.samAccountName
        $homepage = $user.homepage
        if (!$homepage) { Add-Log error "$samid,Homepage not set,Skipping" $WhatIf; continue }
        [string]$id = $user.employeeID
        if (!$id) { Add-Log error "$samid,ID not set" $WhatIf; continue }
  
        Write-Debug "Process $samid`?"
  
        ($guser = . $gam info user $samid) *>$null
        if ( [string]$guser -match $samid ) {
            # Begin check Gsuite and reset password
            Write-Verbose $user.samAccountName
            # Begin PW Reset Process. 
            # looking for 'passwordsLastSet date' = 'account create date'.
            if (($user.created.DateTime -eq $user.passwordlastset.DateTime)) {
                # Query SIS DB for data
                $filledTempPwQuery = 'SELECT DISTINCT BD FROM STU WHERE ID = {0} AND BD IS NOT NULL' -f $user.employeeID
                $tempPwQueryResult = Invoke-SQLCommand -Server $SQLServer -Database $SQLDatabase -Credential $SQLCredential -Query $filledTempPwQuery
                if (!$tempPwQueryResult) { 
                    Write-Verbose ('{0},No data returned' -f $user.samAccountName)
                    continue
                }
                $tempPw = [string](Get-date $tempPwQueryResult.BD -Format yyMMdd)
                $securePw = ConvertTo-SecureString -String $tempPw -AsPlainText -Force
                Add-Log pwreset "$samid" $WhatIf
                Set-ADAccountPassword -Identity $samid -NewPassword $securePw -Reset -Confirm:$False -Whatif:$WhatIf
            } # End PW Reset Process
            # Reactivate GSuite account
            if ( [string]$guser -match 'Account Suspended: True' ) {
                Add-Log update "$samid GSuite Account: Enabled" $WhatIf
                .$gam update user suspended off *>$null
            }
            # Re-Check GSUite 
            ($guser = . $gam info user $samid) *>$null
            if ([string]$guser -match "Account Suspended: True") {
                Add-Log warning "$samid,User account is still suspended" $WhatIf
            }
        }
        else { Write-Verbose "$samid not found in GSUite" } # End Check Gsuite and reset password
    } # End Process AD Results
    #  Wait x seconds and run again until $endTime
    if ( !$WhatIf ) {
        "Next run at $((get-Date).AddSeconds($waitTime))"
        foreach ($n in $waitTime..1) {
            Start-Sleep 1
            # Write-Progress -Activity "Processing User Objects" -Status Waiting -Sec $n
        }
    }
} until ((get-date) -ge $endTime )
Add-Log action "Tearing Down AD Sessions"
Get-PSSession | Remove-PSSession -WhatIf:$false