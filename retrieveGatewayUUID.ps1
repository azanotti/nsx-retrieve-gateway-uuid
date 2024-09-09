$ErrorActionPreference = 'Stop'

#Bypass certificate verification
if ($PSVersionTable.PSEdition -eq 'Core') {
	$Script:PSDefaultParameterValues = @{
        "invoke-restmethod:SkipCertificateCheck" = $true
        "invoke-webrequest:SkipCertificateCheck" = $true
	}
} else {
	Add-Type @"
		using System.Net;
		using System.Security.Cryptography.X509Certificates;
		public class TrustAllCertsPolicy : ICertificatePolicy {
			public bool CheckValidationResult(
				ServicePoint srvPoint, X509Certificate certificate,
				WebRequest request, int certificateProblem) {
				return true;
			}
		}
"@

	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


#Functions
function Get-NsxApiHeaders(){
    $username = "admin"
    $pass = Read-Host "$username password" -AsSecureString
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
    $userpass  = $username + ":" + $password
    $bytes= [System.Text.Encoding]::UTF8.GetBytes($userpass)
    $encodedlogin=[Convert]::ToBase64String($bytes)
    $authheader = "Basic " + $encodedlogin
    $header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $header.Add("Authorization",$authheader)
    return $header
}

#Connect to NSX-T Manager
$nsxTurl = Read-Host "NSX-T Manager (IP or FQDN)"

$headers = Get-NsxApiHeaders
try{
    $response = Invoke-WebRequest -Uri "https://$nsxTurl/api/v1/reverse-proxy/node/health" -UseBasicParsing -DisableKeepAlive -Headers $headers
} catch {
    Write-Error "Error: $_"
    exit
}
if($response.StatusCode -ne 200){
    Write-Error "NSX-T returned status code != 200" -ForegroundColor "Red"
    $response
    exit
} else {
    write-host "Connection successful" -ForegroundColor "Green"
}

#Retrieve all edge node IDs
try{
    $nodes = Invoke-RestMethod -Method GET -Uri "https://$nsxTurl/api/v1/transport-nodes?node_types=EdgeNode" -Headers $headers;
} catch {
    Write-Error "Error while retrieve edge nodes: $($_)"
    $nodeResponse
    exit
}


if($nodes) {
    if($nodes.results.Count -lt 1){
        Write-Error "No edge nodes found"
    }
}

#Get gateway name from user
$tgu = Read-Host "TGU"

#Get all T0s
try{
    $t0s = Invoke-RestMethod -Method GET -Uri "https://$nsxTurl/policy/api/v1/infra/tier-0s" -Headers $headers;
} catch {
    Write-Error "Error while retrieve t0 gateways: $($_)"
    $t0s
    exit
}

if($t0s) {
    if($t0s.results.Count -lt 1){
        Write-Error "No t0 gateways found"
    }
}

#Get all T1s
try{
    $t1s = Invoke-RestMethod -Method GET -Uri "https://$nsxTurl/policy/api/v1/infra/tier-1s" -Headers $headers;
} catch {
    Write-Error "Error while retrieve t1 gateways: $($_)"
    $t1s
    exit
}

if($t1s) {
    if($t1s.results.Count -lt 1){
        Write-Error "No t1 gateways found"
    }
}

#Get gateway ID from name
$gatewayIds = @()

$id = 0

foreach($t0 in $t0s.results){
    if($t0.display_name.Contains($tgu)){
        $gatewayObject = [PSCustomObject]@{
            ID = $id
			GatewayName = $t0.display_name
            GatewayType = "Tier-0"
            GatewayID = $t0.unique_id
        }
        $gatewayIds += $gatewayObject
        $id = $id + 1
    }
}

foreach($t1 in $t1s.results){
    if($t1.display_name.Contains($tgu)){
        $gatewayObject = [PSCustomObject]@{
            ID = $id
			GatewayName = $t1.display_name
            GatewayType = "Tier-1"
            GatewayID = $t1.unique_id
        }
        $gatewayIds += $gatewayObject
        $id = $id + 1
    }
}

#Ask for gateway selection if >1 found
if($gatewayIds.Count -gt 1){
    Write-Host "Found the following gateways:"
    $gatewayIds | Format-Table
    $gatewayNumber = Read-Host "Choose an ID"
    $selectedGateway = $gatewayIds | Where-Object { $_.ID -eq $gatewayNumber }
} else {
    Write-Host "Found the following gateway:"
    $gatewayIds | Format-Table
    $selectedGateway = $gatewayIds[0]
}

#Search gateway in all edge nodes
$routers = @()
$id = 0
foreach($node in $nodes.results){
    $nodeId = $node.node_id
    $nodeName = $node.display_name
    try{
        $nodeRoutersResponse = Invoke-RestMethod -Method GET -Uri "https://$nsxTurl/api/v1/transport-nodes/$nodeId/node/logical-routers/diagnosis" -Headers $headers;
    } catch {
        Write-Error "Error while retrieving node router(s): $($_)"
        $nodeRouters
        exit
    }
    if($nodeRoutersResponse){
        if($nodeRoutersResponse.results.Count -gt 0){
            foreach($router in $nodeRoutersResponse.results){
                if($router.mp_router_uuid -eq $selectedGateway.GatewayID){
                    $gatewayObject = [PSCustomObject]@{
                        ID = $id
                        RouterName = $router.name
                        RouterType = $router.router_type
                        RouterUUID = $router.logical_router_uuid
                        Node = $nodeName
                    }
                    $routers += $gatewayObject
                    $id = $id + 1
                }
            }
        }
    }
}

Write-Host "Identified the following Logical Router(s):"
$routers | Format-Table