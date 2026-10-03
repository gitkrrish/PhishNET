$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}

# Final comprehensive test
"=== FINAL VERIFICATION ==="

"1. CONNECTION TEST:"
$conn = irm -Method GET -Headers $headers http://localhost:8787/api/ip-intelligence/test-connection
$conn.data

"2. CREATE (via analyzeIp auto-persist):"
$ipBody = @{target="192.0.2.1"} | ConvertTo-Json
$created = irm -Method POST -Body $ipBody -ContentType "application/json" -Headers $headers http://localhost:8787/api/analyze/ip
$created.riskScore
$created.id

"3. READ from DynamoDB:"
$read = irm -Method GET -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
$read.data.riskScore
$read.data.version
$read.data.IPAddress

"4. UPDATE:"
$updateBody = @{riskScore=95} | ConvertTo-Json
$updated = irm -Method PUT -Body $updateBody -ContentType "application/json" -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
$updated.data.riskScore
$updated.data.version

"5. READ AFTER UPDATE:"
$read2 = irm -Method GET -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
$read2.data.riskScore
$read2.data.version

"6. DELETE:"
$deleted = irm -Method DELETE -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
$deleted.data

"7. FINAL CLEANUP VERIFICATION:"
try {
    $final = irm -Method GET -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
    "FAIL - Record still exists"
} catch {
    "PASS - Record properly deleted (404)"
}

"=== EXISTING VIPER TRACE APIS ==="
$cases = irm -Method GET -Headers $headers http://localhost:8787/api/cases
"Cases: " + $cases.data.Count

$audit = irm -Method GET -Headers $headers http://localhost:8787/api/audit
"Audit entries: " + $audit.data.Count

$actors = irm -Method GET -Headers $headers http://localhost:8787/api/intel/actors
"Threat Actors: " + $actors.data.Count