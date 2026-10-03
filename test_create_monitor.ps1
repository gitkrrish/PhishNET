$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}

"=== CREATE MONITOR FOR ACTOR-001 ==="
$monitorInput = @{
    name = "Test Actor Monitoring"
    targetType = "ACTOR"
    targetId = "ACTOR-001"
    targetValue = "ShadowFox"
    frequency = "EVERY_15_MIN"
    severity = "MEDIUM"
    conditions = @("NEW_ACTIVITY", "NEW_INFRASTRUCTURE", "NEW_RELATIONSHIP")
    status = "ACTIVE"
    notes = "Synthetic test monitor for ACTOR-001"
} | ConvertTo-Json -Depth 10

$created = irm -Method POST -Body $monitorInput -ContentType "application/json" -Headers $headers http://localhost:8787/api/intel/monitoring
$created.data | Select-Object id, name, targetType, targetId, status, runtimeState, frequency, collectionIntervalSeconds | Format-Table -AutoSize

$monitorId = $created.data.id

"=== GET MONITOR DETAIL ==="
$detail = irm -Method GET -Headers $headers "http://localhost:8787/api/intel/monitoring/$monitorId"
$detail.data | Select-Object id, name, targetType, targetId, status, runtimeState, frequency, effectiveFrequency, collectionIntervalSeconds, capability | Format-Table -AutoSize

"=== MONITOR CAPABILITY ==="
$detail.data.capability | Format-Table -AutoSize

"=== RUN MONITOR NOW ==="
$runResult = irm -Method POST -Headers $headers "http://localhost:8787/api/intel/monitoring/run/$monitorId"
$runResult.data | Format-Table -AutoSize

"=== GET MONITOR EVENTS ==="
$events = irm -Method GET -Headers $headers "http://localhost:8787/api/intel/monitoring/$monitorId/events"
$events.data | Select-Object id, checkAt, status, observationsSeen, triggeredAlertIds, message | Format-Table -AutoSize

"=== GET MONITOR ALERTS ==="
$alerts = irm -Method GET -Headers $headers "http://localhost:8787/api/intel/monitoring/$monitorId/alerts"
$alerts.data | Select-Object id, severity, title, reason, raisedAt, status | Format-Table -AutoSize

"=== MONITORING STATS AFTER CREATE ==="
$stats = irm -Method GET -Headers $headers http://localhost:8787/api/intel/monitoring/stats
$stats.data | Format-Table -AutoSize

"=== LIST ALL MONITORS ==="
$allMonitors = irm -Method GET -Headers $headers http://localhost:8787/api/intel/monitoring
$allMonitors.data | Select-Object id, name, targetType, targetId, status, runtimeState, checkCount, triggerCount | Format-Table -AutoSize

"=== MONITORS FOR ACTOR-001 ==="
$monitorsForActor = irm -Method GET -Headers $headers http://localhost:8787/api/intel/monitoring/entity/ACTOR/ACTOR-001
$monitorsForActor.data | Select-Object id, name, targetType, targetId, status | Format-Table -AutoSize