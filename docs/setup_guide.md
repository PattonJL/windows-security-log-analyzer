# Setup and Deployment Guide

## Prerequisites

- Windows 10, Windows 11, or Windows Server
- Python 3.8 or higher
- PowerShell (run as Administrator for Security Log access)
- A Gmail account with 2-Step Verification enabled

---

## Step 1 — Verify Python Access

Open PowerShell and confirm:

```powershell
python --version
pip --version
```

Then confirm you can read the Security Event Log:

```powershell
Get-WinEvent -LogName Security -MaxEvents 5 | Select-Object TimeCreated, Id, Message
```

If you get "Access Denied", right-click PowerShell and choose
**Run as Administrator**, then try again.

---

## Step 2 — Generate a Gmail App Password

1. Sign in to your Google Account
2. Go to **Security → 2-Step Verification** (must be enabled)
3. Search for **"App Passwords"** in the search bar
4. Create a new App Password — name it something like `Security Analyzer`
5. Copy the 16-character password — you will not see it again

---

## Step 3 — Set Environment Variables

Copy `setup_env.example.ps1`, rename the copy to `setup_env.ps1`,
and fill in your real credentials.

Open an **Administrator PowerShell** and run:

```powershell
.\setup_env.ps1
```

**Delete `setup_env.ps1` immediately after running it.** It contains
your App Password. The example file with placeholders is safe to keep.

Close and reopen PowerShell before the next step.

---

## Step 4 — Test the Analyzer

```powershell
cd "C:\path\to\windows-security-log-analyzer"

# Basic test — last 24 hours, default threshold of 5
python login_analyzer.py

# Full test with email alert
python login_analyzer.py --days 7 --threshold 1 --email
```

Check that:
- The formatted report prints to the terminal
- A `failed_logins_YYYYMMDD_HHMMSS.txt` file appears in the folder
- If suspects were found and `--email` was passed, the alert arrived

---

## Step 5 — Schedule with Task Scheduler

1. Open **Task Scheduler** (`Win + S` → search "Task Scheduler")
2. Click **"Create Task"** in the right panel (not Basic Task)
3. **General tab**
   - Name: `Security-LogAnalyzer-Daily`
   - Check **"Run with highest privileges"**
4. **Triggers tab**
   - Click New → Daily → Set time to **6:00 AM**
5. **Actions tab**
   - Program/script: `python`
   - Add arguments: `"C:\full\path\to\login_analyzer.py" --hours 24 --threshold 5 --email`
   - Start in: `"C:\full\path\to\windows-security-log-analyzer"`
6. Click OK and confirm with your Windows credentials

The analyzer will now run automatically every morning before the
workday starts.

---

## CLI Reference

```powershell
python login_analyzer.py [--hours N | --days N] [--threshold N] [--email]
```

| Flag | Default | Description |
|---|---|---|
| `--hours N` | `24` | Scan the last N hours |
| `--days N` | — | Scan the last N days (overrides `--hours`) |
| `--threshold N` | `5` | Failed logins before flagging an account |
| `--email` | off | Send Gmail alert if suspects are detected |

`--email` only fires when suspects are actually found.
A clean scan sends no email.