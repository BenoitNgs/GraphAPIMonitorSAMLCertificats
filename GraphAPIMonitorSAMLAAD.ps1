################################# Start Functions #################################
Function Get-OAuthGraphAPITocken{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$Resource,
    [Parameter(Mandatory=$true)][string]$ClientID,
    [Parameter(Mandatory=$true)][string]$ClientSecret,
    [Parameter(Mandatory=$true)][string]$TenantName
    )


    $ReqTokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        client_Id     = $clientID
        Client_Secret = $clientSecret
    } 

    $TokenOAuth = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody

    return $TokenOAuth
}


Function Get-GraphAPIQuery{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]$TokenOAuth,
    [Parameter(Mandatory=$true)][string]$apiUrlQuery
    )

    $Data = @()
    
    $resQuery = Invoke-RestMethod -Headers @{Authorization = "$($TokenOAuth.token_type) $($TokenOAuth.access_token)"} -Uri $apiUrlQuery -Method Get
    $Data += $resQuery.Value

    while($resquery."@odata.nextLink"){
        $resQuery = Invoke-RestMethod -Headers @{Authorization = "$($TokenOAuth.token_type) $($TokenOAuth.access_token)"} -Uri $resquery."@odata.nextLink" -Method Get
        $Data += $resQuery.Value
    }

    return $Data
}


Function zGet-AADAppsEnterpriseSAMLCertStatus{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]$GraphAPIResQueryApplications
    )

    $lstAADApps = $GraphAPIResQueryApplications

    $res=@()

    foreach($AADApps in $lstAADApps){

        if(!$([string]::IsNullOrEmpty($AADApps.preferredTokenSigningKeyThumbprint))){

            foreach($AADAppsPasswordCredentials in $AADApps.passwordCredentials){

                $dataCollect = New-Object System.object
                $dataCollect | Add-Member -name ‘AppDisplayName’ -MemberType NoteProperty -Value $AADApps.displayName
                $dataCollect | Add-Member -name ‘AppId’ -MemberType NoteProperty -Value $AADApps.appId
                $dataCollect | Add-Member -name ‘id’ -MemberType NoteProperty -Value $AADApps.id
                $dataCollect | Add-Member -name ‘preferredSingleSignOnMode’ -MemberType NoteProperty -Value $AADApps.preferredSingleSignOnMode
                $dataCollect | Add-Member -name ‘preferredTokenSigningKeyThumbprint’ -MemberType NoteProperty -Value $AADApps.preferredTokenSigningKeyThumbprint

                $dataCollect | Add-Member -name ‘passwordCredentialscustomKeyIdentifier’ -MemberType NoteProperty -Value $AADAppsPasswordCredentials.customKeyIdentifier
                $dataCollect | Add-Member -name ‘passwordCredentialsendDateTime’ -MemberType NoteProperty -Value $AADAppsPasswordCredentials.endDateTime
                $dataCollect | Add-Member -name ‘passwordCredentialskeyId’ -MemberType NoteProperty -Value $AADAppsPasswordCredentials.keyId
                $dataCollect | Add-Member -name ‘passwordCredentialsTTLInDays’ -MemberType NoteProperty -Value $(New-TimeSpan –Start $(get-date) -End $(get-date $AADAppsPasswordCredentials.endDateTime)).Days
 
                foreach($AADAppsKeyCredentials in $AADApps.keyCredentials){
                    if($AADAppsKeyCredentials.usage -eq "Sign" -and $AADAppsKeyCredentials.customKeyIdentifier -eq $AADAppsPasswordCredentials.customKeyIdentifier){
                        $dataCollect | Add-Member -name ‘keyCredentialsSignCustomKeyIdentifier’ -MemberType NoteProperty -Value $AADAppsKeyCredentials.customKeyIdentifier
                        $dataCollect | Add-Member -name ‘keyCredentialsSignDisplayName’ -MemberType NoteProperty -Value $AADAppsKeyCredentials.displayName
                        $dataCollect | Add-Member -name ‘keyCredentialsSignEndDateTime’ -MemberType NoteProperty -Value $AADAppsKeyCredentials.endDateTime
                        $dataCollect | Add-Member -name ‘keyCredentialsSignKeyId’ -MemberType NoteProperty -Value $AADAppsKeyCredentials.keyId
                        $dataCollect | Add-Member -name ‘keyCredentialsSignTTLInDays’ -MemberType NoteProperty -Value $(New-TimeSpan –Start $(get-date) -End $(get-date $AADAppsKeyCredentials.endDateTime)).Days
                    }

                    if($AADAppsKeyCredentials.usage -eq "Verify" -and $AADAppsKeyCredentials.customKeyIdentifier -eq $AADAppsPasswordCredentials.customKeyIdentifier){
                        $dataCollect | Add-Member -name ‘keyCredentialsVerifyCustomKeyIdentifier’ -MemberType NoteProperty -Value $AADAppsKeyCredentials.customKeyIdentifier
                        $dataCollect | Add-Member -name ‘keyCredentialsVerifyDisplayName’ -MemberType NoteProperty -Value $AADAppsKeyCredentials.displayName
                        $dataCollect | Add-Member -name ‘keyCredentialsVerifyEndDateTime’ -MemberType NoteProperty -Value $AADAppsKeyCredentials.endDateTime
                        $dataCollect | Add-Member -name ‘keyCredentialsVerifyKeyId’ -MemberType NoteProperty -Value $AADAppsKeyCredentials.keyId
                        $dataCollect | Add-Member -name ‘keyCredentialsVerifyTTLInDays’ -MemberType NoteProperty -Value $(New-TimeSpan –Start $(get-date) -End $(get-date $AADAppsKeyCredentials.endDateTime)).Days
                    }
                }
                $res += $dataCollect                
            }
        }
    }

    return $res
}

################################# End Functions #################################

################################# Start Cst and var #################################

$cstResource = "https://graph.microsoft.com"
$cstClientID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx"
$cstClientSecret = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx"
$cstTenantID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx"

$strQueryURLAPI = 'https://graph.microsoft.com/v1.0/servicePrincipals'

################################# End Cst and var #################################

################################# Start Main #################################

$TokenOAuth = Get-OAuthGraphAPITocken -Resource $cstResource -ClientID $cstClientID -ClientSecret $cstClientSecret -TenantName $cstTenantID
zGet-AADAppsEnterpriseSAMLCertStatus -GraphAPIResQueryApplications $(Get-GraphAPIQuery -TokenOAuth $TokenOAuth -apiUrlQuery $strQueryURLAPI)

################################# End Main #################################
