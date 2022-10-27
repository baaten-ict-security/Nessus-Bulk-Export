# Nessus-Bulk-Export
When performing vulnerability assessments using Nessus Professional, it is likely you end up with a lot of separate scans. Nessus does not support bulk exporting all scans, so you need to manually export each scan. This is annoying and a lot of work. This PowerShell script can be used for bulk downloading all scan results (in .nessus format) from a specific Nessus folder.

# Getting started
Before you can use this script you need to obtain a secretKey and accessKey from Nessus. This is a two step process, for which you use open source API client [Insomnia](https://insomnia.rest/):

1. POST request to "/session" with the follwing JSON body: `{"username":"yourusernamehere","password":"yourpasswordhere"}`.The response contains a token, which you need for step 2.

2. PUT request to "/session/keys" wit the following header: `X-Cookie: token=yourtokenhere`. The response contains an AccessKey and a SecretKey. Use these in the script. 

Also make sure to fill in the correct Nessus hostname or IP in the **$apibaseURI**.

Authors: Dennis Baaten (Baaten ICT Security) and Ferry Niemeijer
Thanks to: Johan Moritz (VeriftyIT)
