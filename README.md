# Reset-NewStudentPasswords

Resets passwords for newly created, non-staff student accounts in Active Directory and Google Workspace. The script is intended to run as a Jenkins job.

## What the script does

Each run looks for AD users who:

- Were created within the last five days.
- Have an `employeeID` and `employeeType` of `student`.
- Have never logged on.
- Either have not had a password set, or were created at the same time as their current password was set.

For each eligible user, the script looks up the Google account using the AD `HomePage` value and retrieves a temporary password from SQL using the AD `EmployeeID`. It skips users without matching Google data or a SQL result whose `tempPw` does not contain six digits. For remaining users, it removes the configured secondary AD group membership (if present), waits for removal, resets the AD password, adds the group membership back, and unsuspends the Google account if needed. If the AD `gecos` value has no digits, it sets it to `0` for an elementary department or `100` otherwise.

The script repeats this process every `LoopDelaySeconds` seconds and stops at `StopTime`. The default delay is 900 seconds (15 minutes).

## Requirements

- Windows PowerShell with access to the required Active Directory domain controller and permissions to read and update the relevant users and group memberships.
- The `ActiveDirectory`, `dbatools`, and `CommonScriptFunctions` PowerShell modules.
- SQL connectivity and credentials with permission to run the configured temporary-password query.
- GAM 7 at `C:\GAM7\gam.exe`, authenticated for the Google Workspace tenant. GAM authentication must be available to the account running the job.
- A SQL query that accepts the `@id` parameter and returns a `tempPw` column containing a six-digit password.

## Run manually

Pass AD and SQL credentials as `PSCredential` values and provide the SQL connection, query, and AD group:

```powershell
$adCredential = Get-Credential
$sqlCredential = Get-Credential

.\Reset-NewStudentPasswords.PS1 `
  -ADCredential $adCredential `
  -SQLServer 'sql-server' `
  -SQLDatabase 'database' `
  -SQLCredential $sqlCredential `
  -TempPWQuery "SELECT * TOP 1 FROM STU WHERE ID = @id" `
  -SecondaryGroup 'Password-Policy-Students-6-12' `
  -StopTime '3:00 PM' `
  -LoopDelaySeconds 1200 `
  -WhatIf
```

`-WhatIf` is the recommended mode for a test run. It passes WhatIf through to the AD update commands and prevents the Google unsuspend command from running. Remove `-WhatIf` only when you intend to make changes.

The script also supports `-Verbose` for additional diagnostic output.

## Jenkins

`jenkins.ps1` builds the script parameters from these Jenkins environment variables:

| Variable                     | Purpose                                                         |
| ---------------------------- | --------------------------------------------------------------- |
| `JOB_NAME`                   | Repository/script name used to clone and invoke the job script. |
| `AD_USER`, `AD_PW`           | AD credential.                                                  |
| `SIS_SERVER`, `SIS_DATABASE` | SQL Server and database.                                        |
| `SIS_USER`, `SIS_PW`         | SQL credential.                                                 |

The wrapper uses the SQL query shown in the manual example and the `Password-Policy-Students-6-12` group. It currently sets `$test = $true` and passes it as `-WhatIf`, so it runs in test mode by default. Review this setting before enabling password changes. Store credentials in Jenkins credentials/environment configuration; do not commit secrets to the repository.

`params.ps1` provides a similar parameter set for an environment where the referenced credential and SQL variables are already defined.
