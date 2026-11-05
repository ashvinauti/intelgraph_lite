# IntelGraph Lite: clean setup on Windows 10/11

This guide takes a Windows PC from nothing to a running dashboard. It takes
about 10 minutes. Every command is for **PowerShell** (Start menu, type
`PowerShell`, open *Windows PowerShell*). You don't need administrator rights.

**Contents**

1. [Install Python and Git](#1-install-python-and-git)
2. [Download IntelGraph Lite](#2-download-intelgraph-lite)
3. [Run the setup script](#3-run-the-setup-script)
4. [Add your API keys](#4-add-your-api-keys)
5. [Start it](#5-start-it)
6. [Optional: AI with a fully local model (Ollama)](#6-optional-ai-with-a-fully-local-model-ollama)
7. [Everyday use](#7-everyday-use)
8. [Updating](#8-updating)
9. [Where your data lives](#9-where-your-data-lives)
10. [Troubleshooting](#10-troubleshooting)
11. [Removing an old install / uninstalling](#11-removing-an-old-install--uninstalling)

---

## 1. Install Python and Git

Skip any that you already have.

```powershell
winget install Python.Python.3.12
winget install Git.Git
```

**Close PowerShell and open a new window**, so it finds the new programs. Then check:

```powershell
py --version     # Python 3.12.x  (any 3.11 or newer works, including the Microsoft Store one)
git --version
```

> If `winget` isn't recognised, install **App Installer** from the Microsoft
> Store, or download Python from python.org and Git from git-scm.com. In the
> Python installer, tick **"Add python.exe to PATH"**.

## 2. Download IntelGraph Lite

Put it in your user folder, **not on the Desktop**. The Desktop is often
synced by OneDrive, which would upload the program files and your API keys.

```powershell
cd $HOME
git clone https://github.com/ashvinauti/intelgraph_lite.git
cd intelgraph_lite
```

The repository is private, so Git opens a browser window the first time. Sign
in to GitHub there and the download continues.

## 3. Run the setup script

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

The script:

* checks Python
* creates a private Python environment in `.venv`
* installs IntelGraph Lite with the AI extra
* creates your `.env` file from `.env.example`
* lists the intelligence sources

It's safe to run again, and it never overwrites an existing `.env`.

> `-ExecutionPolicy Bypass` applies to this one command only; it doesn't change
> your system settings. Add `-NoAI` to skip the optional Claude package.

## 4. Add your API keys

```powershell
notepad .env
```

Fill in the keys you have after the `=`, then save. Leave a line empty to keep
that source off. No quotes are needed.

```ini
# Threat-intelligence sources (all optional; free accounts work)
SHODAN_API_KEY=your-shodan-key
VIRUSTOTAL_API_KEY=your-virustotal-key
OTX_API_KEY=your-otx-key
ABUSECH_AUTH_KEY=

# AI analyst + false-positive triage, with Claude
ANTHROPIC_API_KEY=your-key
# Only if you use a gateway/reseller instead of Anthropic directly:
# ANTHROPIC_BASE_URL=https://the-gateway-host
# IGLITE_AI_MODEL=the-model-name-it-expects
```

Then check which sources are on:

```powershell
.\.venv\Scripts\iglite.exe sources
```

Every source whose key you added should say `enabled`. DNS, RDAP, crt.sh and
InternetDB need no key and are always on.

**Keep `.env` private.** It's excluded from Git, so it's never uploaded, but
don't paste keys into chats, emails or screenshots. If a key has been exposed,
regenerate it on that service's website and replace it here.

## 5. Start it

**Double-click `start.cmd`** in the `intelgraph_lite` folder.

Or, from PowerShell:

```powershell
.\.venv\Scripts\iglite.exe serve --watch --open
```

Your browser opens **http://127.0.0.1:8765** with the dashboard, and live
network monitoring starts. To stop, close the window, or press **Ctrl+C** in
PowerShell.

The dashboard listens only on your own computer (`127.0.0.1`), so other
devices can't reach it and Windows Firewall doesn't need to ask.

First things to try:

| Where | What |
|-------|------|
| **Overview** tab | Paste an IP, domain or URL into *Investigate*. |
| **Live network** tab | Your current connections, which program made each one, and a verdict for each. |
| **Routes** tab | Trace the path to any address (uses Windows' built-in `tracert`). |
| **Analyst** tab | Ask the AI a question in plain language (needs an AI key or Ollama). |
| Any alert | **False positive** / **Confirm**, or **AI check** to let the triage agent investigate it. |

## 6. Optional: AI with a fully local model (Ollama)

Use this if you want the AI features without sending anything off your
computer. It's slower and less accurate than Claude, especially without a
graphics card.

```powershell
winget install Ollama.Ollama
```

Open a **new** PowerShell window, then download a model. That's a one-time
download of about 4.7 GB:

```powershell
ollama pull qwen2.5:7b
```

Add these lines to `.env`:

```ini
IGLITE_AI_PROVIDER=ollama
IGLITE_AI_MODEL=qwen2.5:7b
```

Restart IntelGraph Lite. The Analyst tab and the alerts card then say
*"qwen2.5:7b via Ollama at localhost:11434 (on this computer)"*. Ollama runs
in the background after installation; if it isn't running, the dashboard says
so.

To switch back to Claude, remove the two lines (or set
`IGLITE_AI_PROVIDER=anthropic`) and restart.

**Automatic AI triage of new alerts** is on by default, with at most 20 runs
an hour. To control it, add one line to `.env`:

```ini
IGLITE_AI_TRIAGE=manual   # only when you click "AI check"
IGLITE_AI_TRIAGE=off      # never
```

## 7. Everyday use

* **Start:** double-click `start.cmd`.
* **Command line:** open PowerShell in the folder and activate the environment
  once per window. After that you can just type `iglite`:

  ```powershell
  cd $HOME\intelgraph_lite
  .\.venv\Scripts\Activate.ps1
  iglite investigate 8.8.8.8 example.com
  iglite alerts                 # recent alerts and their AI verdicts
  iglite triage --open          # let the AI check every open alert
  iglite fp 203.0.113.66 --note "office VPN"   # mark a false positive
  iglite trace google.com
  iglite ask "What should I look at first?"
  ```

  If `Activate.ps1` is blocked, run this once:
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. Or skip activation and
  type `.\.venv\Scripts\iglite.exe` instead of `iglite`.

* **Shortcut on the Desktop:** right-click `start.cmd` > *Show more options* >
  *Send to* > *Desktop (create shortcut)*.

## 8. Updating

```powershell
cd $HOME\intelgraph_lite
git pull
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Your `.env`, settings and database are kept, and the database upgrades itself
on first start.

## 9. Where your data lives

| What | Where |
|------|-------|
| Program | `C:\Users\<you>\intelgraph_lite` |
| API keys | `C:\Users\<you>\intelgraph_lite\.env`, or `C:\Users\<you>\.iglite\.env` to share them between folders |
| Database (indicators, alerts, marks, AI verdicts) | `C:\Users\<you>\.iglite\iglite.db` |
| Optional settings | `iglite.toml` in the program folder. Copy `iglite.example.toml` to start. |

* **Back up:** copy `iglite.db` while IntelGraph Lite is stopped.
* **Start fresh:** delete it.
* **Free space:** `iglite prune --days 90` removes data older than 90 days.

## 10. Troubleshooting

| Problem | Fix |
|---------|-----|
| `py` / `python` is not recognised | Close and reopen PowerShell after installing. Still missing? Reinstall Python with "Add python.exe to PATH" ticked. |
| Typing `python` opens the Microsoft Store | Settings > Apps > Advanced app settings > **App execution aliases** > turn off *python.exe* and *python3.exe*. |
| "running scripts is disabled on this system" | Use the exact command in step 3 (it bypasses this once), or run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |
| `iglite` is not recognised | The environment isn't active in this window. Run `.\.venv\Scripts\Activate.ps1`, or use `.\.venv\Scripts\iglite.exe`. |
| A source still says `missing key` | Check the file is called exactly `.env`, not `.env.txt`: `Get-ChildItem -Force .env*`. Rename with `Rename-Item .env.txt .env`. Check there's no space before the `=`. Restart IntelGraph Lite after editing. |
| A key is rejected (`check the API key`) | Copy it again from the service's website: no spaces, no quotes, whole key. |
| "The analyst isn't set up yet" | Claude: add `ANTHROPIC_API_KEY` to `.env` and rerun `setup.ps1` (installs the AI extra). Ollama: see step 6. The message names the exact problem. |
| "Ollama isn't running" / "model isn't downloaded" | Start *Ollama* from the Start menu; run `ollama pull qwen2.5:7b`. |
| Port 8765 is already in use | `.\.venv\Scripts\iglite.exe serve --watch --open --port 8766` |
| Live network shows no processes | Normal for some system services. Ordinary programs show by name. No admin rights are needed. |
| `git pull` says local changes would be overwritten | You edited a project file. `git stash` sets your changes aside, then `git pull` again. `.env` is never affected. |
| `pip` fails with SSL / proxy errors on a work PC | Ask IT for the proxy, then `$env:HTTPS_PROXY="http://proxy:port"` before running `setup.ps1`. |

## 11. Removing an old install / uninstalling

Removing an earlier copy, for example one in `Desktop\Intelgraph\New folder`:

1. Stop it (close its window, or Ctrl+C).
2. If you want to keep your keys, copy its `.env` into the new folder first.
3. Delete the old folder.

Also remove an old user-level install, if `pip` ever put one there. That
happens when `pip install .` runs without the environment active:
`python -m pip uninstall iglite`. This is the Python that was used. If that
was the Microsoft Store Python, you can keep it, or remove it from
Settings > Apps once the winget one is installed.

To uninstall completely:

```powershell
Remove-Item -Recurse -Force $HOME\intelgraph_lite   # program, .venv and .env
Remove-Item -Recurse -Force $HOME\.iglite           # database and shared .env
```

Python, Git and Ollama can be removed from Settings > Apps if you no longer
need them. To free Ollama's model space first, run `ollama rm qwen2.5:7b`.
