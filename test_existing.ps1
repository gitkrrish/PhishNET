$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}

# Test various Viper Trace APIs
"=== Test /api/analyze/ip ==="
$ipBody = @{target="8.8.8.8"} | ConvertTo-Json
irm -Method POST -Body $ipBody -ContentType "application/json" -Headers $headers http://localhost:8787/api/analyze/ip | Select-Object id, targetType, ip, riskScore, verdict

"=== Test /api/cases ==="
irm -Method GET -Headers $headers http://localhost:8787/api/cases | Select-Object data

"=== Test /api/audit ==="
irm -Method GET -Headers $headers http://localhost:8787/api/audit | Select-Object data

"=== Test /api/analyses ==="
irm -Method GET -Headers $headers http://localhost:8787/api/analyses | Select-Object data

"=== Test /api/intel/actors ==="
irm -Method GET -Headers $headers http://localhost:8787/api/intel/actors | Select-Object data