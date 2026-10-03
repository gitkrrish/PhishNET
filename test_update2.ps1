$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}
$updateBody = @{riskScore=90} | ConvertTo-Json -Depth 10
irm -Method PUT -Body $updateBody -ContentType "application/json" -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1