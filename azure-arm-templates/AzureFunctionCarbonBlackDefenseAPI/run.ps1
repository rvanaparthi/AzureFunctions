<#  
    Title:          CarbonBlack Data Connector
    Language:       PowerShell
    Version:        1.0
    Author:         Microsoft
    Last Modified:  5/19/2020
    Comment:        Inital Release

    DESCRIPTION
    This Function App calls the CarbonBlack Defense REST API (https://developer.carbonblack.com/reference/carbon-black-cloud/cb-defense/latest/rest-api/) to pull the CarbonBlack
    Audit and Event logs. The response from the CarbonBlack API is recieved in JSON format. This function will build the signature and authorization header 
    needed to post the data to the Log Analytics workspace via the HTTP Data Connector API. The Function App will post each log type to their individual tables in Log Analytics, for example,
    CarbonBlackAuditLogs_CL and CarbonBlackEvents_CL.
#>
# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# The function will call the Carbon Black API and retrieve 
function CarbonBlackAPI()
{
    $workspaceId = $env:workspaceId
    $workspaceSharedKey = $env:workspaceKey
    $hostName = $env:uri
    $apiSecretKey = $env:apiKey
    $apiId = $env:apiId
    $notifapikey = $env:SIEMapiKey #change variable names to SIEMapikey
    $notifapiId = $env:SIEMapiId
    $time = $env:timeInterval
    $AuditLogTable = "CarbonBlackAuditLogs"
    $EventLogTable = "CarbonBlackEvents"
    $NotificationTable  = "CarbonBlackNotifications"


    $startTime = [System.DateTime]::UtcNow.AddMinutes(-$($time)).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $now = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

 
    if($apiSecretKey -eq '<Optional>' -or  $apiId -eq '<Optional>'  -or [string]::IsNullOrWhitespace($apiSecretKey) -or  [string]::IsNullOrWhitespace($apiId))
    {
        Write-Host "Please pass the Notification for security API Key and API Id as they are Optional"
    }
    else
    {
    $authHeaders = @{
        "X-Auth-Token" = "$($apiSecretKey)/$($apiId)"
    }
    $auditLogsResult = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/auditlogs"))
    $eventsResult = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/event?startTime=$($startTime)&endTime=$($now)"))

    if ($auditLogsResult.success -eq $true)
    {
        $AuditLogsJSON = $auditLogsResult.notifications | ConvertTo-Json -Depth 5
        if (-not([string]::IsNullOrWhiteSpace($AuditLogsJSON)))
        {
            Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($AuditLogsJSON)) -logType $AuditLogTable;
        }
        else
        {
            Write-Host "No new Carbon Black Audit Events as of $([DateTime]::UtcNow)"
        }
    }
    if ($eventsResult.success -eq $true)
    {
        $EventLogsJSON = $eventsResult.results | ConvertTo-Json -Depth 5
        if (-not([string]::IsNullOrWhiteSpace($EventLogsJSON)))
        {
            Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($EventLogsJSON)) -logType $EventLogTable;
        }
        else
        {
            Write-Host "No new Carbon Black Events as of $([DateTime]::UtcNow)"
        }
      }
    }

    if($notifapiKey -eq '<Optional>' -or  $notifapiId -eq '<Optional>'  -or [string]::IsNullOrWhitespace($notifapiKey) -or  [string]::IsNullOrWhitespace($notifapiId))
    {   
         Write-Host "Please pass the Notification API Key and API Id as they are left Optional"   
    }
    else
    {                
        $authHeaders = @{"X-Auth-Token" = "$($notifapiKey)/$($notifapiId)"}
        $notifications = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/notification"))
        if ($notifications.success -eq $true)
        {                
            $NotifLogJson = $notifications.notifications | ConvertTo-Json -Depth 5       
            if (-not([string]::IsNullOrWhiteSpace($NotifLogJson)))
            {
                Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($NotifLogJson)) -logType $NotificationTable;
            }
            else
            {
                    Write-Host "No new Carbon Black Notifications as of $([DateTime]::UtcNow)"
            }
                 
        }      
    }    
}


# Create the function to create the authorization signature
function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date;
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource;
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash);
    $keyBytes = [Convert]::FromBase64String($sharedKey);
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256;
    $sha256.Key = $keyBytes;
    $calculatedHash = $sha256.ComputeHash($bytesToHash);
    $encodedHash = [Convert]::ToBase64String($calculatedHash);
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash;
    return $authorization;
}

# Create the function to create and post the request
function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $TimeStampField = "DateValue"
    $method = "POST";
    $contentType = "application/json";
    $resource = "/api/logs";
    $rfc1123date = [DateTime]::UtcNow.ToString("r");
    $contentLength = $body.Length;
    $signature = Build-Signature -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource;
    $uri = "https://$($customerId).ods.opinsights.azure.com$($resource)?api-version=2016-04-01";
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    };
    $response = Invoke-WebRequest -Body $body -Uri $uri -Method $method -ContentType $contentType -Headers $headers -UseBasicParsing
    return $response.StatusCode
}

# Execute the Function to Pull CarbonBlack data and Post to the Log Analytics Workspace
CarbonBlackAPI

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"