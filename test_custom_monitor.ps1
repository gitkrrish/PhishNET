$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}

"=== TEST CUSTOM MONITOR WITH MULTIPLE TARGETS ==="
$customInput = @{
    name = "Custom Multi-Target Monitor"
    targetType = "CUSTOM"
    frequency = "EVERY_15_MIN"
    severity = "HIGH"
    conditions = @("NEW_ACTIVITY", "NEW_INFRASTRUCTURE", "NEW_TRANSACTION")
    status = "ACTIVE"
    targets = @(
        @{ entityType = "ACTOR"; entityId = "ACTOR-001"; conditions = @("NEW_ACTIVITY", "NEW_INFRASTRUCTURE") }
        @{ entityType = "WALLET"; entityId = "WAL-001"; conditions = @("NEW_TRANSACTION") }
        @{ entityType = "HANDLE"; entityId = "HDL-001"; conditions = @("NEW_PLATFORM") }
    )
    notes = "Synthetic custom monitor for multiple entities"
} | ConvertTo-Json -Depth 10

$created = irm -Method POST -Body $customInput -ContentType "application/json" -Headers $headers http://localhost:8787/api/intel/monitoring
$created.data | Select-Object id, name, monitorKind, targetType, status, runtimeState | Format-Table -AutoSize

$customMonitorId = $created.data.id

"=== GET CUSTOM MONITOR DETAIL ==="
$detail = irm -Method GET -Headers $headers "http://localhost:8787/api/intel/monitoring/$customMonitorId"
$detail.data | Select-Object id, name, monitorKind, targets | Format-Table -AutoSize
$detail.data.targets | Format-Table -AutoSize

"=== RUN CUSTOM MONITOR ==="
$runResult = irm -Method POST -Headers $headers "http://localhost:8787/api/intel/monitoring/run/$customMonitorId"
$runResult.data | Format-Table -AutoSize

"=== GET CUSTOM MONITOR EVENTS ==="
$events = irm -Method GET -Headers $headers "http://localhost:8787/api/intel/monitoring/$customMonitorId/events"
$events.data | Select-Object id, checkAt, status, observationsSeen, triggeredAlertIds, message | Format-Table -AutoSize

"=== MONITORING STATS ==="
$stats = irm -Method GET -Headers $headers http://localhost:8787/api/intel/monitoring/stats
$stats.data | Format-Table -AutoSize