# Nessus-Bulk-Export
When performing vulnerability assessments using Nessus Professional, it is likely you end up with a lot of separate scans. Nessus does not support bulk exporting all scans, so you need to manually export each scan. This is annoying and a lot of work. This PowerShell script can be used for bulk downloading all scan results (in .nessus format) from a specific Nessus folder.

# Getting started
Before you can use this script you need to obtain a secretKey and accessKey from Nessus. This is a two step process, for which you use open source API client [Insomnia](https://insomnia.rest/):

1. POST request to "/session" with the follwing JSON body: `{"username":"yourusernamehere","password":"yourpasswordhere"}`.The response contains a token, which you need for step 2.

2. PUT request to "/session/keys" wit the following header: `X-Cookie: token=yourtokenhere`. The response contains an AccessKey and a SecretKey. Use these in the script. 

Also make sure to fill in the correct Nessus hostname or IP in the **$apibaseURI**.

# Limitations and known issues
* This script does not work with scan history due to a limitation of the Nessus API. While this feature is documented by Tenable in the /api/ path of you Nessus Professional instance, it does not work. By default the most recent (current) scan is downloaded.
* On the 9th of September 2023 I discovered a bug in Nessus Professional: if you use a forward slash in the name of your scan, the export of a .Nessus (XML) file failes for both the API and the GUI. The GUI shows a '500 - Internal Server Error'. The issue was reported to Tenable.

# Authors
* Dennis Baaten (Baaten ICT Security)
* Ferry Niemeijer

Special thanks to Johan Moritz (VeriftyIT)
