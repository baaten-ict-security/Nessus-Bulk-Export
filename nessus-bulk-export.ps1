## Nessus Bulk Export (NBE)
##
## When performing vulnerability assessments using Nessus Professional, it is 
## likely you end up with a lot of separate scans. Nessus does not support
## bulk exporting all scans, so you need to manually export each scan. 
## This is annoying and a lot of work. This PowerShell script can be used for bulk
## downloading all scan results (in .nessus format) from a specific Nessus folder.
##
## GETTING STARTED / READ THIS FIRST:
## Before you can use this script you need to obtain a secretKey and accessKey 
## from Nessus. This is a two step process, for which you use open source API
## client Insomnia (https://insomnia.rest/):
##
## 1. 
## POST request to "/session" with the follwing JSON body: {"username":"yourusernamehere","password":"yourpasswordhere"}
## The response contains a token, which you need for step 2.
##
## 2.
## PUT request to "/session/keys" wit the following header: X-Cookie: token=yourtokenhere
## The response contains an AccessKey and a SecretKey. Use these in the script. 
##
## Also make sure to fill in the correct Nessus hostname or IP in the $apibaseURI.
##
## Authors: Dennis Baaten (Baaten ICT Security) and Ferry Niemeijer
## Thanks to: Johan Moritz (VeriftyIT)

Clear

## Define some variables for later use

# Acesskey and Secretkey for Nessus authentication
$AccessKey = "your-acceskey-here"
$SecretKey = "your-secretkey-here"

# Create authentication header for GET and POST requests
$Headers =@{ "X-ApiKeys" = "accessKey=$AccessKey ;secretKey=$SecretKey " }
$Body ='{"format":"nessus"}'

# Define API URI's
$apibaseURI = 'https://nessus-hostname-or-ip-here:8834'
$foldersURI = $apibaseURI+'/folders'
$fileidURI = $apibaseURI+'/scans/'

#UTC epoch adjustment for current timezone
$timezone = (Get-TimeZone)
if ($timezone.SupportsDaylightSavingTime -eq $True) {
    $timeadjust =  ($timezone.BaseUtcOffset.TotalSeconds + 3600)
}
else {
    $timeadjust = ($timezone.BaseUtcOffset.TotalSeconds)
}

## Let user select the directory to export all files to
$application = New-Object -ComObject Shell.Application
While (!$outputdir) {
    $outputdir = ($application.BrowseForFolder(0, 'Nessus Bulk Export Script: where do you want to store the scan exports? ', 0)).Self.Path 
}

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Get all folders
$folders = Invoke-RestMethod -Method GET -URI $foldersURI -Headers $Headers

Write-host "Nessus folder list:"
foreach ($folder in $folders.folders) { 
    Write-host $folder.id "-"$folder.name
}

Write-host "`r`n"

# Read the folder ID entered by the user
[int] $foldernr = Read-Host -Prompt "Enter the ID of the folder to fetch all scan reports in .nessus format"
$scansURI = $apibaseURI+"/scans?folder_id=$foldernr"

# Get all scans within selected folder
$scans = Invoke-RestMethod -Method GET -URI $scansURI -Headers $Headers 

Write-host "`r`n"
Write-host "Scans in selected folder" $foldernr ":"
foreach ($scan in $scans.scans) { 
    #Get the scan's last_modification_date epoch (which is UTC) and convert it to local timezone
    $lastmoddate = (([System.DateTimeOffset]::FromUnixTimeSeconds($scan.last_modification_date+$timeadjust)).DateTime).ToString("yyMMdd_HHmm")
    Write-host $scan.id "-" $scan.name "-" $lastmoddate
}

Write-host "`r`n"

#Get file ID's of scans

$fileids = @()
Foreach ($scan in $scans.scans) { 
    if ($scan.status -eq "completed") {
        $URI = $fileidURI + $scan.id + "/export"
        $fileid = Invoke-RestMethod -Method POST -URI $URI -Headers $Headers -Body $Body -ContentType application/json
    
        $obj = New-Object psobject -Property @{            
                scanid = $scan.id
                fileid = $fileid.file 
                scanname = $scan.name
                lastmoddate = (([System.DateTimeOffset]::FromUnixTimeSeconds($scan.last_modification_date+$timeadjust)).DateTime).ToString("yyMMdd_HHmm")
            }
        Clear-Variable fileid
        $fileids += $obj            
    } 
}

# Check export status and download when status is "Ready".
foreach ($file in $fileids) {
    $statusURI = $fileidURI + $file.scanid + "/export/" + $file.fileid + "/status"
    $downloadURI = $fileidURI + $file.scanid + "/export/" + $file.fileid + "/download"

    $filestatus = Invoke-RestMethod -Method GET -URI $statusURI -Headers $Headers

    while ( $success -ne "Yes" ) {         
        if ($filestatus.status -eq "ready") { 
            $success = "Yes"
            $exporttime = Get-Date -Format "yyMMdd_HHmm"
            $filename = 'NBE - ' + $file.scanid + ' - ' + $file.scanname + ' - ' + $file.lastmoddate

            Invoke-WebRequest -Method GET -Headers $Headers -Uri $downloadURI -UseBasicParsing -OutFile $outputdir\$filename".nessus"
            write-host "Export finished for scan" $file.scanid: $filename".nessus"
        } else { 
            write-host $file.scanname "has status"$filestatus.status". Will try again in 10 seconds"
            sleep -Seconds 10 
            $filestatus = Invoke-RestMethod -Method GET -URI $statusURI -Headers $Headers
        }
    }
    Clear-Variable success
    Clear-Variable downloadURI
}

Write-host "`r`n***Finished exporting all scan reports***" 
 