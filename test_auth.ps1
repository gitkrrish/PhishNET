$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in