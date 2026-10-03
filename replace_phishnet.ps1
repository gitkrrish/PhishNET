$content = Get-Content "D:\sss\tracewall\src\pages\darkweb\AddIntelligencePage.tsx" -Raw
$content = $content -replace "phishnet-intelligence-dataset.json", "viper-trace-intelligence-dataset.json"
Set-Content "D:\sss\tracewall\src\pages\darkweb\AddIntelligencePage.tsx" -Value $content