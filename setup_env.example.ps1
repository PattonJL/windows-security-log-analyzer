# ─────────────────────────────────────────────────────────────────
# setup_env.example.ps1
#
# INSTRUCTIONS:
#   1. Copy this file and rename the copy to setup_env.ps1
#   2. Replace the placeholder values below with your real credentials
#   3. Run the copy once in an Administrator PowerShell session
#   4. DELETE the copy immediately after — it will contain your password
#
# This example file is safe to keep. It contains no real credentials.
# ─────────────────────────────────────────────────────────────────

[System.Environment]::SetEnvironmentVariable(
    "ALERT_EMAIL_SENDER",
    "your-sender@gmail.com",
    "User"
)
[System.Environment]::SetEnvironmentVariable(
    "ALERT_EMAIL_PASSWORD",
    "your-16-character-app-password",
    "User"
)
[System.Environment]::SetEnvironmentVariable(
    "ALERT_EMAIL_RECEIVER",
    "your-recipient@gmail.com",
    "User"
)

Write-Host "`n[✓] Environment variables set." -ForegroundColor Green
Write-Host "[!] Close and reopen PowerShell before running the analyzer." -ForegroundColor Yellow
Write-Host "[!] DELETE this file now — it contains your App Password." -ForegroundColor Red