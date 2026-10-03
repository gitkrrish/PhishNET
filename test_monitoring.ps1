$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}

"=== MONITORING CAPABILITIES ==="
$caps = irm -Method GET -Headers $headers http://localhost:8787/api/intel/monitoring/capabilities
$caps.data.targetTypes | Select-Object key, label, entityTypes, defaultConditions | Format-Table -AutoSize

"=== MONITORING STATS ==="
$stats = irm -Method GET -Headers $headers http://localhost:8787/api/intel/monitoring/stats
$stats.data | Format-Table -AutoSize

"=== EXISTING MONITORS ==="
$monitors = irm -Method GET -Headers $headers http://localhost:8787/api/intel/monitoring
$monitors.data | Select-Object id, name, targetType, targetId, status, runtimeState, frequency, checkCount, triggerCount | Format-Table -AutoSize

"=== MONITORS FOR ACTOR-001 ==="
$monitorsForActor = irm -Method GET -Headers $headers http://localhost:8787/api/intel/monitoring/entity/ACTOR/ACTOR-001
$monitorsForActor.data | Select-Object id, name, targetType, targetId, status | Format-Table -AutoSize