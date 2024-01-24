$global:params = @{
 DCs              = 'Mainframe.chico.usd', 'optimus.chico.usd', 'kickoff.chico.usd'
 ADSearchBase     = 'OU=Students,OU=Users,OU=Domain_Root,DC=chico,DC=usd'
 ADCredential     = $adtasks
 SQLServer        = $sisServer
 SQLDatabase      = $sisDB
 SQLCredential    = $AeriesCreds
 TempPWQuery      = 'SELECT DISTINCT BD as tempPw FROM STU WHERE ID = {0} AND BD IS NOT NULL'
 SecondaryGroup   = 'Password-Students-6-12'
 StopTime         = '6:00 PM'
 LoopDelaySeconds = 900
}
$params
ls -recurse -filter *.ps1 | Unblock-File