$pwd = "demo-password"
$body = @{email="analyst@tracewall.demo"; password=$pwd} | ConvertTo-Json
$auth = irm -Method POST -Body $body -ContentType "application/json" http://localhost:8787/api/auth/sign-in
$token = $auth.token
$headers = @{Authorization = "Bearer $token"}

"=== TEST PAUSE/RESUME/DISABLE/ENABLE ==="
$monitorId = "MON-MUPR973H-14"

"--- PAUSE ---"
$pause = irm -Method POST -Headers $headers "http://localhost:8787/api/intel/monitoring/$monitorId/pause"
$pause.data | Select-Object id, status, runtimeState | Format-Table -AutoSize

"--- RESUME ---"
$resume = irm -Method POST -Headers $headers "http://localhost:8787/api/intel/monitoring/$monitorId/resume"
$resume.data | Select-Object id, status, runtimeState | Format-Table -AutoSize

"--- DISABLE ---"
$disable = irm -Method POST -Headers $headers "http://localhost:8787/api/intel/monitoring/$monitorId/disable"
$disable.data | Select-Object id, status, runtimeState | Format-Table -AutoSize

"--- ENABLE ---"
$enable = irm -Method POST -Headers $headers "http://localhost:8787/api/intel/monitoring/$monitorId/enable"
$enable.data | Select-Object id, status, runtimeState | Format-Table -AutoSize

"=== TEST MONITOR ANALYSIS ==="
$analysis = irm -Method POST -Body '{"enrich":true}' -ContentType "application/json" -Headers $headers "http://localhost:8787/api/intel/monitoring/$monitorId/analyze"
$analysis.data | Select-Object monitor, observed, priority, inference | Format-Table -AutoSize
$analysis.data.observed | Format-Table -AutoSize

"=== TEST ALERT ATTACHMENT TO INVESTIGATION ==="
$investigations = irm -Method GET -Headers $headers http://localhost:8787/api/intel/investigations
$investigations.data | Select-Object id, title, status | Format-Table -AutoSize

"=== TEST LIST SOURCES ==="
$sources = irm -Method GET -Headers $headers http://localhost:8787/api/intel/sources
$sources.data | Select-Object id, name, type, status, health_status, access_mode | Format-Table -AutoSize