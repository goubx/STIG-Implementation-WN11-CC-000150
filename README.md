## Initial Scan and Finding Selection

The initial scan returned over 150 failed audits out of 263 total checks. STIG findings on a default Azure image are dense, which makes this a good first target.

The finding I selected to remediate:

WN11-CC-000150 - The user must be prompted for a password on resume from sleep (plugged in).

## I found the stig through stiagaview.com

### I am now about to begin the manual remediation.

1. First im going to check to see if the registration key even exists in the Registry Editor.

[image]

As you can see the key does not exist within the windows folder

2. I am now going to create the correct path

[image]

As seen above i have created the proper keys for this audit to pass.

### It seems my first attempt did not work and the audit failed once again.

[image]

I am now going to attempt to resolve this by configuring the policy.

to do this, I have to:

> Computer Configuration >> Administrative Templates >> System >> Power Management >> Sleep Settings >> "Require a password when a computer wakes (plugged in)" to "Enabled".

[image]

I have now enabled it within the group policy.

### I am now going to run a scan to authenticate this.

[image]

As you can see above, the scan proved the audit failure for WN11-CC-000150 is now a success.

## Now I am going to undo everything I did and create a PowerShell script to produce the same result.

I have now switched it back to the previous setting of 'not configured'. 

### I am going to run another scan to confirm that the manual remediation has been removed.

[image]

The scan has confirmed the manual remediation has been removed, due to the failed status.

### Now i am going to undo everything I did and create a PowerShell script to produce the same result.

Since I have confirmed the settings are set back to before, im going to run this powershell script i curated with claude.

```powershell
# STIG WN11-CC-000150: Require password on resume from sleep (plugged in)
$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
$Name    = 'ACSettingIndex'
$Desired = 1   # 1 = Enabled (password required on wake while plugged in)

# Create the registry path if it does not exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
    Write-Host "Created registry path: $RegPath"
}

# Apply the ACSettingIndex value
Set-ItemProperty -Path $RegPath -Name $Name -Value $Desired -Type DWord -Force
Write-Host "Set $Name to $Desired in $RegPath"

# Verify
$Current = (Get-ItemProperty -Path $RegPath -Name $Name).$Name
if ($Current -eq $Desired) {
    Write-Host "Compliant: $Name = $Current"
} else {
    Write-Warning "Non-compliant: $Name = $Current, expected $Desired"
}
```

### I am now going to rerun scan the confirm that the script worked
