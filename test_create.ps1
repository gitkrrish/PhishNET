$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}
$ipBody = @{target="192.0.2.1"} | ConvertTo-Json
irm -Method POST -Body $ipBody -ContentType "application/json" -Headers $headers http://localhost:8787/api/analyze/ip