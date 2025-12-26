
# Golden-IT Email Validation v2.1 (with real-time server sync)
# - GUI + Inline License kept
# - v1-style Google Sheet selectors kept:
#     Share button: @id=docs-titlebar-share-client-button
#     Input field : @aria-haspopup=listbox
#     Valid parse : data-hovercard-id from RBsUnc
# - NEW: Webhook sync to cPanel PHP endpoint (post valid emails in real-time)

import os, re, json, threading, queue, math, platform, uuid
import requests
from datetime import datetime
from time import sleep
from tkinter import *
from tkinter import ttk, filedialog, messagebox

# ==== DrissionPage ====
from DrissionPage import ChromiumOptions, ChromiumPage

# ---------- App Meta ----------
APP_NAME    = "Golden-IT Email Validation"
APP_VERSION = "v2.1"

# ---------- License ----------
LICENSE_FILENAME = "license.json"
WHATSAPP_NUMBER  = "+8801948241312"
CLIENT_VERSION   = "v1"
EXPIRY_DATE      = datetime(2026, 10, 30)

def _resource_path(rel: str) -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, rel)

def _load_license() -> dict:
    try:
        p = _resource_path(LICENSE_FILENAME)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f) or {}
    except Exception:
        pass
    return {}

def _save_license(data: dict):
    try:
        p = _resource_path(LICENSE_FILENAME)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data or {}, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def _basic_key_ok(key: str) -> bool:
    key = (key or "").strip()
    return bool(key) and len(key) >= 12

class LicenseDialog(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("License Activation")
        self.configure(bg="#0b132b")
        self.geometry("460x240")
        self.resizable(False, False)
        self.result = None
        self.grab_set(); self.focus_force()

        hdr = Frame(self, bg="#2986cc"); hdr.pack(fill=X)
        Label(hdr, text=APP_NAME, bg="#2986cc", fg="white", font=("Segoe UI", 12, "bold")).pack(padx=12, pady=8)

        body = Frame(self, bg="#0b132b"); body.pack(fill=BOTH, expand=True, padx=16, pady=12)
        Label(body, text="Enter your license key to continue:", bg="#0b132b", fg="#eaeaea").pack(anchor="w")
        self.key_var = StringVar()
        ent = Entry(body, textvariable=self.key_var, width=52, bg="#16213e", fg="#eaeaea", insertbackground="#eaeaea", relief="flat")
        ent.pack(pady=8, anchor="w"); ent.focus_set()
        Label(body, text=f"Need a key? WhatsApp: {WHATSAPP_NUMBER}", bg="#0b132b", fg="#9fb4ff").pack(anchor="w", pady=(6,10))

        btns = Frame(body, bg="#0b132b"); btns.pack(anchor="e")
        Button(btns, text="Activate", width=12, bg="#1bf703", fg="#0b132b", relief="flat", command=self._ok).pack(side=LEFT, padx=4)
        Button(btns, text="Exit", width=10, bg="#f25f5c", fg="white", relief="flat", command=self._cancel).pack(side=LEFT, padx=4)

    def _ok(self):
        key = self.key_var.get().strip()
        if not _basic_key_ok(key):
            messagebox.showwarning("License", "Invalid license key. Please check and try again.")
            return
        self.result = {"key": key, "version": CLIENT_VERSION, "activated_at": datetime.now().isoformat()}
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()

def enforce_license_or_exit():
    if datetime.now() > EXPIRY_DATE:
        messagebox.showerror("Software Expired", f"Software is expired, contact developer\nWhatsApp: {WHATSAPP_NUMBER}")
        raise SystemExit(0)
    data = _load_license()
    if not _basic_key_ok(data.get("key", "")):
        tmp = Tk(); tmp.withdraw()
        dlg = LicenseDialog(tmp); tmp.wait_window(dlg)
        if not dlg.result:
            tmp.destroy(); raise SystemExit(0)
        _save_license(dlg.result); tmp.destroy()

# ---------- Real-time Server Sync (Webhook to cPanel/PHP) ----------
# Toggle ON/OFF
ENABLE_WEBHOOK_SYNC = True

# Your server endpoint + API key + per-PC client key
SERVER_ENDPOINT_URL = "https://gittoken.store/valid-api/collect-valids.php"
SERVER_API_KEY      = "Wd9h4-D!8%sB*9X@p#s6k-L&h7mQ$d4x"
CLIENT_KEY          = "PC-1"   # Give each machine a unique label (or leave empty to auto-fill hostname)

def get_client_key():
    # prefer configured label; else hostname; else MAC
    return CLIENT_KEY or platform.node() or str(uuid.getnode())

def webhook_sync_append(valid_list, account_email, batch_id=""):
    """Push valid emails to your cPanel endpoint in real-time."""
    try:
        if not ENABLE_WEBHOOK_SYNC or not valid_list:
            return
        payload = {
            "emails": list(valid_list),
            "account": account_email,
            "client_key": get_client_key(),
            "batch_id": batch_id or f"B{int(datetime.now().timestamp())}"
        }
        headers = {"X-API-Key": SERVER_API_KEY, "Content-Type": "application/json"}
        r = requests.post(SERVER_ENDPOINT_URL, json=payload, headers=headers, timeout=12)
        if r.status_code >= 400:
            ui_log(f"Server sync failed [{r.status_code}]: {r.text[:300]}")
            return
        ui_log(f"Server sync: pushed {len(valid_list)} valid(s).")
    except Exception as e:
        ui_log(f"Server sync exception: {e}")

# ---------- Global State ----------
driver: ChromiumPage | None = None
stop_flag = False
pause_flag = False

gmail_accounts = []            # list of dicts: email, password, recovery, status, checks_done
failed_gmails = []
checks_per_gmail = 5
batch_size = 100

email_files = []
all_emails = []
processed_emails = set()
valid_emails = []
invalid_emails = []

current_email_batch = []
current_check_count = 0

# ---------- UI Helpers (thread-safe log/updates) ----------
ui_q = queue.Queue()

def ui_log(msg: str):
    ui_q.put(("log", msg))

def ui_status(msg: str):
    ui_q.put(("status", msg))

def ui_counts():
    ui_q.put(("counts", len(set(valid_emails)), len(invalid_emails), len(processed_emails), len(all_emails)))

def ui_accounts_refresh():
    ui_q.put(("accounts", [(a["email"], a["status"], a["checks_done"]) for a in gmail_accounts]))

def ts(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------- Email utils ----------
def is_valid_email(email):
    return re.match(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$', (email or "").strip()) is not None

def clean_email_list(emails):
    seen, out = set(), []
    for e in emails:
        e2 = e.strip().lower()
        if is_valid_email(e2) and e2 not in seen:
            out.append(e2); seen.add(e2)
    return out

# ---------- Browser ----------
def init_browser(headless=False, proxy=""):
    global driver
    if driver:
        try: driver.quit()
        except: pass
        driver = None
    co = ChromiumOptions()
    co.incognito(on_off=True)
    if headless:
        co.headless(on_off=True)
    if proxy:
        try: co.set_proxy(proxy)
        except: pass
    driver = ChromiumPage(addr_or_opts=co)
    return driver

def close_browser():
    global driver
    if driver:
        try: driver.quit()
        except: pass
    driver = None
    return True

# ---------- File I/O ----------
def read_email_list(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = [ln.strip() for ln in f if ln.strip()]
        cleaned = clean_email_list(raw)
        # non-destructive: write to *_cleaned.txt
        base, ext = os.path.splitext(path)
        cleaned_path = f"{base}_cleaned.txt"
        with open(cleaned_path, "w", encoding="utf-8") as out:
            out.write("\n".join(cleaned))
        ui_log(f"Cleaned {os.path.basename(path)} -> {os.path.basename(cleaned_path)} ({len(cleaned)} emails)")
        return cleaned
    except Exception as e:
        ui_log(f"Error reading {path}: {e}")
        return []

def read_gmail_accounts(path):
    accounts = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line: continue
                parts = line.split(":")
                email = parts[0].strip(); pwd = parts[1].strip()
                rec = parts[2].strip() if len(parts) >= 3 else ""
                accounts.append({"email": email, "password": pwd, "recovery": rec, "status": "pending", "checks_done": 0})
    except Exception as e:
        ui_log(f"Error reading Gmail accounts: {e}")
    return accounts

def save_failed_gmails():
    try:
        with open("failed_gmails.txt", "w", encoding="utf-8") as f:
            for a in failed_gmails:
                f.write(f"{a['email']}:{a['password']}:{a.get('recovery','')}\n")
    except Exception:
        pass

# ---------- Google interactions (v1-style selectors) ----------
def get_valid_emails_from_dialog():
    """Read RBsUnc container, return emails from data-hovercard-id (v1 logic)."""
    try:
        html = driver('@class=RBsUnc', timeout=3).html
    except Exception:
        try: html = driver('role:dialog', timeout=2).html
        except Exception: html = ""
    found = set()
    if html:
        for m in re.findall(r'data-hovercard-id="([^"]+@[^"]+)"', html, flags=re.I):
            found.add(m.strip().lower())
    return found

def login_to_gmail(account):
    """Basic Gmail login; keep simple like your original."""
    try:
        init_browser(headless_var.get() == 1, proxy_var.get().strip())
        driver.get("https://accounts.google.com/ServiceLogin")
        sleep(10)

        mail_input = driver('@name=identifier', timeout=10) or driver('@type=email', timeout=10)
        if not mail_input: raise Exception("Email input not found")
        mail_input.input(account["email"])
        (driver('@id=identifierNext', timeout=6) or driver("text:Next", timeout=6)).click()
        sleep(10)

        pwd_input = driver('@name=Passwd', timeout=10) or driver('@type=password', timeout=10)
        if not pwd_input: raise Exception("Password input not found")
        pwd_input.input(account["password"])
        (driver('@id=passwordNext', timeout=6) or driver("text:Next", timeout=6)).click()
        sleep(30)

        account["status"] = "active"
        ui_status(f"Logged in: {account['email']}")
        ui_accounts_refresh()
        return True
    except Exception as e:
        account["status"] = "error"
        ui_status(f"Login error for {account['email']}: {e}")
        ui_accounts_refresh()
        return False

def get_next_valid_gmail():
    # already active and not exceeded
    for a in gmail_accounts:
        if a["status"] == "active" and a["checks_done"] < checks_per_gmail_var.get():
            return a
    # pending -> login
    for a in gmail_accounts:
        if a["status"] == "pending" and a["checks_done"] < checks_per_gmail_var.get():
            if login_to_gmail(a):
                return a
            else:
                failed_gmails.append(a)
    # if everyone either completed or error, stop
    return None

def process_email_batch():
    """Your original batch logic, unchanged in spirit (v1 selectors)."""
    global current_email_batch, current_check_count, processed_emails

    unprocessed = [e for e in all_emails if e not in processed_emails]
    if not unprocessed:
        return True

    account = get_next_valid_gmail()
    if not account:
        ui_status("No valid Gmail accounts available")
        return False

    # batch slice
    size = min(batch_size_var.get(), len(unprocessed))
    current_email_batch = unprocessed[:size]
    emails = current_email_batch

    ui_status(f"Checking {len(emails)} with {account['email']} (Check {account['checks_done'] + 1}/{checks_per_gmail_var.get()})")

    try:
        sheet_url = sheet_url_var.get().strip()
        if not sheet_url:
            raise Exception("Google Sheet URL is empty")

        driver.get(sheet_url)
        sleep(2)
        driver('@id=docs-titlebar-share-client-button').click()
        sleep(2)
        driver('@aria-haspopup=listbox').input('\n'.join(emails))

        # wait ~1.5s per 50 emails like your v1
        loops = int(len(emails) / 50) + 1
        for i in range(loops):
            if stop_flag: return False
            if pause_flag:
                ui_status("Paused..."); 
                while pause_flag and not stop_flag: sleep(0.2)
                ui_status("Resumed")
            ui_status(f"Waiting for validation... {i+1}")
            sleep(1.5)

        found_valid = get_valid_emails_from_dialog()
        current_valid = [e for e in emails if e.lower() in found_valid]
        current_invalid = [e for e in emails if e.lower() not in found_valid]

        # commit to local memory
        valid_emails.extend(current_valid)
        invalid_emails.extend(current_invalid)
        for e in emails: processed_emails.add(e)

        # UI + local files
        ui_counts()
        ui_q.put(("lists", list(current_valid), list(current_invalid)))
        with open('valid_mail.txt', 'a', encoding='utf-8') as vf:
            for e in current_valid: vf.write(e + "\n")
        with open('invalid_mail.txt', 'a', encoding='utf-8') as inf:
            for e in current_invalid: inf.write(e + "\n")

        # ==== NEW: real-time server sync ====
        if ENABLE_WEBHOOK_SYNC and current_valid:
            # optionally chunk to avoid payload limits
            chunk = 200
            batch_id = f"B{int(datetime.now().timestamp())}"
            for i in range(0, len(current_valid), chunk):
                webhook_sync_append(current_valid[i:i+chunk], account['email'], batch_id=batch_id)

        # account rotation
        account['checks_done'] += 1
        current_check_count = account['checks_done']
        if account['checks_done'] >= checks_per_gmail_var.get():
            account['status'] = 'completed'
            ui_status(f"Account {account['email']} reached limit; closing browser.")
            close_browser()
        else:
            account['status'] = 'active'
        ui_accounts_refresh()
        return True

    except Exception as e:
        account['status'] = 'error'
        ui_status(f"Error processing batch: {e}")
        ui_accounts_refresh()
        return False

def process_all_emails():
    global stop_flag
    stop_flag = False
    try:
        # load emails from selected files
        all_emails.clear(); processed_emails.clear()
        for p in email_files:
            all_emails.extend(read_email_list(p))
        ui_log(f"Loaded total {len(all_emails)} emails from {len(email_files)} files.")
        ui_counts()

        if not all_emails:
            ui_status("No emails to process."); return

        # start browser now (login later)
        init_browser(headless_var.get() == 1, proxy_var.get().strip())

        while not stop_flag and len(processed_emails) < len(all_emails):
            ok = process_email_batch()
            if not ok:
                # if all accounts are error or exhausted, stop
                no_active = all(a["status"] in ("error","completed") for a in gmail_accounts)
                if no_active: break
                sleep(1.0)
            # progress bar/eta
            done = len(processed_emails); total = len(all_emails)
            pct = (done/total)*100 if total else 0
            ui_q.put(("progress", done, total, pct))
        if not stop_flag:
            ui_status("All emails processed.")
            if failed_gmails: save_failed_gmails()
        else:
            ui_status("Stopped by user.")
    finally:
        close_browser()

# ---------- GUI ----------
enforce_license_or_exit()

root = Tk()
root.title(f"{APP_NAME} • {APP_VERSION}")
root.geometry("1020x800")
root.configure(bg="#0a1224")

accent = "#0ea5e9"
bg = "#0a1224"; panel = "#0f172a"; textc = "#e5e7eb"; field = "#0b1229"
valid_c = "#22c55e"; invalid_c = "#ef4444"; warn_c = "#f59e0b"

# top header
Label(root, text=f"{APP_NAME} {APP_VERSION}", fg=accent, bg=bg, font=("Segoe UI", 18, "bold")).pack(pady=8)

# config vars
sheet_url_var = StringVar(value="https://docs.google.com/spreadsheets/d/1QfQakmpDH4q2Avpf3hXI8MGDTjnHT7mkUc39TsOiDSg/edit?usp=sharing")
batch_size_var = IntVar(value=300)
checks_per_gmail_var = IntVar(value=10)
headless_var = IntVar(value=0)
proxy_var = StringVar(value="")

gmail_file_var = StringVar(value="")
status_var = StringVar(value="Idle")
valid_count_var = IntVar(value=0)
invalid_count_var = IntVar(value=0)
total_var = IntVar(value=0)
processed_var = IntVar(value=0)
eta_var = StringVar(value="--:--:--")

# top row (sheet url + controls + buttons)
top = Frame(root, bg=panel); top.pack(fill=X, padx=10, pady=6)

left_cfg = Frame(top, bg=panel); left_cfg.pack(side=LEFT, fill=X, expand=True)
def L(lab, var, w=72):
    f = Frame(left_cfg, bg=panel); f.pack(anchor="w", pady=2)
    Label(f, text=lab, bg=panel, fg=textc).pack(side=LEFT)
    Entry(f, textvariable=var, width=w, bg=field, fg=textc, insertbackground=textc, relief="flat").pack(side=LEFT, padx=6)
    return f
L("Google Sheet URL: ", sheet_url_var, 72)
cf = Frame(left_cfg, bg=panel); cf.pack(anchor="w", pady=2)
Label(cf, text="Batch Size:", bg=panel, fg=textc).pack(side=LEFT)
Spinbox(cf, from_=1, to=10000, textvariable=batch_size_var, width=6, bg=field, fg=textc, relief="flat").pack(side=LEFT, padx=6)
Label(cf, text="Checks/Account:", bg=panel, fg=textc).pack(side=LEFT)
Spinbox(cf, from_=1, to=1000, textvariable=checks_per_gmail_var, width=6, bg=field, fg=textc, relief="flat").pack(side=LEFT, padx=6)
Checkbutton(cf, text="Headless", variable=headless_var, bg=panel, fg=textc, activebackground=panel, selectcolor=panel).pack(side=LEFT, padx=10)
L("Proxy (http://user:pass@host:port): ", proxy_var, 50)

right_btns = Frame(top, bg=panel); right_btns.pack(side=RIGHT, padx=6)
def bigbtn(txt, cmd, bgc):
    return Button(right_btns, text=txt, command=cmd, width=16, bg=bgc, fg="white", relief="flat", activebackground=bgc)
Button(right_btns, text="Choose Gmail File", command=lambda: choose_gmail_file(), width=18, bg="#1f2937", fg="white", relief="flat").pack(pady=2)
Button(right_btns, text="Choose Email Files", command=lambda: choose_email_files(), width=18, bg="#1f2937", fg="white", relief="flat").pack(pady=2)
bigbtn("Start",   lambda: start_process(),  "#16a34a").pack(pady=(8,2))
row2 = Frame(right_btns, bg=panel); row2.pack()
Button(row2, text="Pause",  command=lambda: pause_process(),  width=8, bg="#374151", fg="white", relief="flat").pack(side=LEFT, padx=2, pady=2)
Button(row2, text="Resume", command=lambda: resume_process(), width=8, bg="#374151", fg="white", relief="flat").pack(side=LEFT, padx=2, pady=2)
bigbtn("Stop",    lambda: stop_process(),   "#ef4444").pack(pady=(2,6))

# status line
stat = Frame(root, bg=bg); stat.pack(fill=X, padx=10)
Label(stat, textvariable=status_var, bg=bg, fg=textc).pack(side=LEFT)
Entry(stat, textvariable=StringVar(), state="disabled", width=60, relief="flat").pack(side=RIGHT)  # placeholder like screenshot

# metrics row
m = Frame(root, bg=bg); m.pack(fill=X, padx=10, pady=6)
def pill(parent, label, var, color):
    f = Frame(parent, bg=panel); f.pack(side=LEFT, padx=6)
    Label(f, text=label, bg=panel, fg=textc).pack(side=LEFT, padx=6)
    Label(f, textvariable=var, bg=panel, fg=color, width=7).pack(side=LEFT, padx=6)
pill(m, "✅ Valid:",   valid_count_var,   valid_c)
pill(m, "❌ Invalid:", invalid_count_var, invalid_c)
pill(m, "📦 Total:",   total_var,         textc)
pill(m, "🔄 Processed:", processed_var,   textc)
pill(m, "⏳ ETA:",     eta_var,           textc)

# middle split
mid = Frame(root, bg=bg); mid.pack(fill=BOTH, expand=True, padx=10, pady=6)
left = Frame(mid, bg=bg); left.pack(side=LEFT, fill=Y)
Label(left, text="Gmail Accounts", bg=bg, fg=accent, font=("Segoe UI", 10, "bold")).pack(anchor="w")
acc_tree = ttk.Treeview(left, columns=("email","status","checks"), show="headings", height=18)
acc_tree.heading("email", text="Email"); acc_tree.column("email", width=260)
acc_tree.heading("status", text="Status"); acc_tree.column("status", width=100)
acc_tree.heading("checks", text="Checks"); acc_tree.column("checks", width=70, anchor="e")
acc_tree.pack(pady=4)

right = ttk.Notebook(mid); right.pack(side=LEFT, fill=BOTH, expand=True, padx=(10,0))
valid_txt = Text(right, bg=field, fg=textc); invalid_txt = Text(right, bg=field, fg=textc); logs_txt = Text(right, bg="#0b0f1c", fg="#cbd5e1")
right.add(valid_txt, text="✅ Current Valid"); right.add(invalid_txt, text="❌ Current Invalid"); right.add(logs_txt, text="📝 Logs")

# footer
foot = Frame(root, bg=bg); foot.pack(fill=X, padx=10, pady=8)
Button(foot, text="Open Output Folder", command=lambda: open_folder("."), bg="#1f2937", fg="white", relief="flat").pack(side=LEFT, padx=4)
Button(foot, text="Open Logs Folder",   command=lambda: open_folder("."), bg="#1f2937", fg="white", relief="flat").pack(side=LEFT, padx=4)
Label(root, text=f"WhatsApps : {WHATSAPP_NUMBER}", bg=bg, fg="#22c55e", font=("Segoe UI", 10, "bold")).pack(anchor="e", padx=14, pady=(0,6))

# ---------- GUI callbacks ----------
def choose_gmail_file():
    p = filedialog.askopenfilename(title="Select Gmail accounts file", filetypes=[("Text", "*.txt"), ("All", "*.*")])
    if not p: return
    gmail_file_var.set(p)
    ui_log(f"Loaded 1 Gmail accounts file from {os.path.basename(p)}")
    # preload & show accounts
    global gmail_accounts
    gmail_accounts = read_gmail_accounts(p)
    ui_log(f"Loaded {len(gmail_accounts)} Gmail accounts from {os.path.basename(p)}")
    ui_accounts_refresh()

def choose_email_files():
    paths = filedialog.askopenfilenames(title="Select email files", filetypes=[("Text", "*.txt"), ("All", "*.*")])
    if not paths: return
    global email_files
    email_files = list(paths)
    ui_log(f"Selected {len(email_files)} email files.")
    # quick count
    tot = 0
    for p in email_files:
        try:
            with open(p, "r", encoding="utf-8") as f: tot += sum(1 for _ in f)
        except: pass
    total_var.set(tot)

def _worker():
    try:
        process_all_emails()
    except Exception as e:
        ui_log(f"Fatal: {e}")

def start_process():
    if not gmail_file_var.get():
        messagebox.showwarning("Start", "Choose a Gmail accounts file first.")
        return
    if not email_files:
        messagebox.showwarning("Start", "Choose one or more email files first.")
        return
    # reset counters
    global stop_flag, pause_flag, valid_emails, invalid_emails, processed_emails
    stop_flag = False; pause_flag = False
    valid_emails.clear(); invalid_emails.clear(); processed_emails.clear()
    valid_txt.delete("1.0", END); invalid_txt.delete("1.0", END); logs_txt.delete("1.0", END)
    # update globals from controls
    ui_status("Starting...")
    threading.Thread(target=_worker, daemon=True).start()

def stop_process():
    global stop_flag
    stop_flag = True
    ui_status("Stopping...")

def pause_process():
    global pause_flag
    pause_flag = True

def resume_process():
    global pause_flag
    pause_flag = False

def restart_process():
    stop_process()
    sleep(0.3)
    start_process()

def open_folder(path):
    try:
        ab = os.path.abspath(path)
        if os.name == "nt": os.startfile(ab)
        elif sys.platform == "darwin": os.system(f'open "{ab}"')
        else: os.system(f'xdg-open "{ab}"')
    except Exception as e:
        messagebox.showerror("Open Folder", str(e))

# ---------- UI pump ----------
def _fmt_eta(done, total):
    # very rough: 1.5s per 50 emails ~ 0.03s per email
    if total <= 0 or done >= total: return "--:--:--"
    remain = total - done
    secs = int(remain * 0.03)  # estimate
    h = secs // 3600; m = (secs % 3600)//60; s = secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def pump():
    try:
        while True:
            kind, *data = ui_q.get_nowait()
            if kind == "log":
                logs_txt.insert(END, f"[{ts()}] {data[0]}\n"); logs_txt.see(END)
            elif kind == "status":
                status_var.set(data[0])
            elif kind == "counts":
                v,i,done,total = data
                valid_count_var.set(v); invalid_count_var.set(i)
                processed_var.set(done); total_var.set(total)
                eta_var.set(_fmt_eta(done,total))
            elif kind == "accounts":
                # refresh tree
                for i in acc_tree.get_children(): acc_tree.delete(i)
                for em, st, ck in data[0]:
                    acc_tree.insert("", END, values=(em, st, ck))
            elif kind == "progress":
                done, total, pct = data
                processed_var.set(done); total_var.set(total)
                eta_var.set(_fmt_eta(done,total))
            elif kind == "lists":
                vlist, ilist = data
                valid_txt.delete("1.0", END); invalid_txt.delete("1.0", END)
                if vlist: valid_txt.insert(END, "\n".join(vlist))
                if ilist: invalid_txt.insert(END, "\n".join(ilist))
    except queue.Empty:
        pass
    root.after(100, pump)

pump()
root.mainloop()
