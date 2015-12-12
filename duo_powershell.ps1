function Execute-Request()
{
Param(
  [Parameter(Mandatory=$True)]
  [string]$Url,
  [Parameter(Mandatory=$True)]
  [string]$Method,
  [Parameter(Mandatory=$True)]
  [string]$Date,
  [Parameter(Mandatory=$True)]
  [string]$Auth,
  [Parameter(Mandatory=$False)]
  [string]$Params
)	
	#$proxy = New-Object System.Net.WebProxy("http://127.0.0.1:8080") #Useful for debugging requests with a tool like Burp Suite
	$r = [System.Net.WebRequest]::Create($Url + "?" + $Params)
	$r.Date = $Date
	#$r.proxy = $proxy #Useful for debugging requests with a tool like Burp Suite
	$r.Method = $Method
	$r.Headers.Add("Authorization",$Auth)
	$resp = $r.GetResponse()
	$reqstream = $resp.GetResponseStream()
	$sr = new-object System.IO.StreamReader $reqstream
	$result = $sr.ReadToEnd()
	return $result 
}

function Get-HMACSHA1([string]$req, [string]$skey){
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA1
    [byte[]]$publicKeyBytes = [System.Text.Encoding]::ASCII.GetBytes($req)
    [byte[]]$privateKeyBytes = [System.Text.Encoding]::ASCII.GetBytes($skey)
    $hmacsha.Key = $privateKeyBytes
    [byte[]]$hash = $hmacsha.ComputeHash($publicKeyBytes)
    $return = [System.BitConverter]::ToString($hash).Replace("-","").ToLower()
    return $return
}

function ConvertTo-Base64([string] $toEncode){
    [byte[]]$toEncodeAsBytes = [System.Text.ASCIIEncoding]::ASCII.GetBytes($toEncode)
    [string]$returnValue = [System.Convert]::ToBase64String($toEncodeAsBytes)
    return $returnValue
}

function GetAdmins() {
	$date = get-date -date (get-date).ToUniversalTime() -format r 
	$reqtype = "GET"
	$reqpath = "/admin/v1/admins"
	$vars = ""
	$req = "$date`n$reqtype`n$apihost`n$reqpath`n$vars"
	$hash = Get-HMACSHA1 $req $skey
	$signature = ConvertTo-Base64($ikey + ":" + $hash)
	$auth = "Basic $($signature)"
	$Headers = @{}
	$Headers.Add('Date',$date)
	$Headers.Add('Authorization',$auth)
	$url = "https://$apihost$reqpath"
	#This is how it's done with Powershell 4
	#$data = Invoke-WebRequest -Uri $url -Headers @{"Date" = $date; "Authorization" = $auth} #-ContentType "application/x-www-form-urlencoded"
	#return $data.Content
	$data = Execute-Request -Url $url -Method $reqtype -Date $Date -Auth $auth
	return $data
}

function GetUserByName($username) {
	$postParams = @{username=$username}
	$date = get-date -date (get-date).ToUniversalTime() -format r 
	$reqtype = "GET"
	$reqpath = "/admin/v1/users"
	$vars = $postParams.keys[0].trim() + "=" + $postParams.values[0].trim()
	$req = "$date`n$reqtype`n$apihost`n$reqpath`n$vars"
	$hash = Get-HMACSHA1 $req $skey
	$signature = ConvertTo-Base64($ikey + ":" + $hash)
	$auth = "Basic $($signature)"
	$Headers = @{}
	$Headers.Add('Date',$date)
	$Headers.Add('Authorization',$auth)
	$url = "https://$apihost$reqpath"
	$data = Execute-Request -Url $url -Method $reqtype -Date $Date -Auth $auth -Params $vars
	return $data
	#This is how it's done with Powershell 4
	#$data = Invoke-WebRequest -Uri $url -Headers $Headers -Body $postParams -ContentType "application/x-www-form-urlencoded"
	#return $data.Content
}

function CreateAdmin() {
	$postParams = @{email="user%40domain.tld";send_email="1";} 
	#Probably should figure out a way to URL encode characters like the @ above 
	#automatically so that this query string builder doesn't run into issues.
	$postParams.Keys | % {
		$val = $val + ($_ + "=" + $postParams.Item($_)) + "&" 
	}  
	$val = $val.Substring(0,$val.Length-1)
	$date = get-date -date (get-date).ToUniversalTime() -format r 
	$reqtype = "POST"
	$reqpath = "/admin/v1/admins/activate"
	$vars = $val
	$req = "$date`n$reqtype`n$apihost`n$reqpath`n$vars"
	$hash = Get-HMACSHA1 $req $skey
	$signature = ConvertTo-Base64($ikey + ":" + $hash)
	$auth = "Basic $($signature)"
	$Headers = @{}
	$Headers.Add('Date',$date)
	$Headers.Add('Authorization',$auth)
	$url = "https://$apihost$reqpath"
	write-host $req
	$data = Execute-Request -Url $url -Method $reqtype -Date $Date -Auth $auth -Params $vars
	return $data
	#This is how it's done with Powershell 4
	#$data = Invoke-WebRequest -Uri $url -Headers $Headers -Body $postParams -ContentType "application/x-www-form-urlencoded"
	#return $data.Content
}

function DeleteAdmin($admin_id) {
	write-host $admin_id "is to be deleted"
	$date = get-date -date (get-date).ToUniversalTime() -format r 
	$reqtype = "DELETE"
	$reqpath = "/admin/v1/admins/" + $admin_id
	$req = "$date`n$reqtype`n$apihost`n$reqpath`n$vars"
	$hash = Get-HMACSHA1 $req $skey
	$signature = ConvertTo-Base64($ikey + ":" + $hash)
	$auth = "Basic $($signature)"
	$Headers = @{}
	$Headers.Add('Date',$date)
	$Headers.Add('Authorization',$auth)
	$url = "https://$apihost$reqpath"
	$data = Execute-Request -Url $url -Method $reqtype -Date $Date -Auth $auth
	return $data
	#This is how it's done with Powershell 4
	#$data = Invoke-WebRequest -Uri $url -Headers $Headers -ContentType "application/x-www-form-urlencoded"
	#return $data.Content
}

function IsActive($upn) {
	$filter = 'UserPrincipalName -eq "{0}"' -f $upn
	$user = get-aduser -Filter $filter
	if ($user -eq $null) {
		#write-host "Not found:" $upn
		return $FALSE
	}
	if ($user.Enabled -eq $FALSE ) {
		#write-host "Not active:" $upn
		return $FALSE
	}
	else {
		return $TRUE
	}
}

function AuditAdmins() {
	$admins = ConvertFrom-Json (GetAdmins)
	foreach( $admin in $admins.response ) { 
		 if (!(IsActive($admin.email) -eq $True)) {
			write-host "need to delete" $admin.email
			DeleteAdmin($admin.admin_id)
		 }
	}
}

$apihost = "your_api_hostname_here"
$skey = "your_secrey_key_here"
$ikey = "your_integration_key"

write-host "Beginning Audit."
(AuditAdmins)
write-host "Audit completed."