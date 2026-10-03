$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}

"=== FINAL VERIFICATION ==="

"1. CONNECTION TEST:"
$conn = irm -Method GET -Headers $headers http://localhost:8787/api/ip-intelligence/test-connection
$conn.data | ConvertTo-Json -Depth 5

"2. CREATE (via analyzeIp auto-persist):"
$ipBody = @{target="192.0.2.1"} | ConvertTo-Json
$created = irm -Method POST -Body $ipBody -ContentType "application/json" -Headers $headers http://localhost:8787/api/analyze/ip
"Created analysis: " + $created.id + " riskScore: " + $created.riskScore

"3. READ from DynamoDB:"
$read = irm -Method GET -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
"READ riskScore: " + $read.data.riskScore + " version: " + $read.data.version + " IPAddress: " + $read.data.IPAddress

"4. UPDATE:"
$updateBody = @{riskScore=95} | ConvertTo-Json
$updated = irm -Method PUT -Body $updateBody -ContentType "application/json" -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
"UPDATE riskScore: " + $updated.data.riskScore + " version: " + $updated.data.version

"5. READ AFTER UPDATE:"
$read2 = irm -Method GET -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
"READ riskScore: " + $read2.data.riskScore + " version: " + $read2.data.version

"6. DELETE:"
$deleted = irm -Method DELETE -Headers $headers http://localhost:8787/api/ip-intelligence/192.0.2.1
"DELETE: " + $deleted.data.success + " ip: " + $deleted.data.ipAddress

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