import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import threading
import pandas as pd
import re, time, random, hashlib, requests, ipaddress
from pathlib import Path
from fake_useragent import UserAgent
from dateutil.parser import parse as parse_date
from stem import Signal
from stem.control import Controller
import webbrowser
from PIL import Image, ImageTk, ImageSequence


# --------------------------- IP ROTATOR OPTIMIZAT ---------------------------

class IPHistory:
    def __init__(self):
        self.seen = set() #se memoreaza ip-urile deja vizitate

    def check(self, ip):
        if ip in self.seen:
            return False  #ip duplicat
        self.seen.add(ip)
        return True #ip nou

#instanta pentru istoricul ip-urilor
ip_history = IPHistory()
stop_rotation = False #control pentru oprirea thread-ului de rotatie
country_filter = "" #nu se filtreaza pe o tara anume

def set_tor_exit_country(country_code): #Se configureaza tara in reteaua tor folosind coduri ISO
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.set_conf("ExitNodes", "{" + country_code + "}")
            controller.set_conf("StrictNodes", "1")
            controller.signal(Signal.NEWNYM)
            return True
    except Exception as e:
        return str(e)

def tor_ip(socks_user: str): # se executa rotatia ip-ului la fiecare 10 secunde si are loc actualizarea cu noul IP
    proxy = f"socks5://{socks_user}:pwd@127.0.0.1:9050"
    proxies = {"http": proxy, "https": proxy}
    ua = UserAgent().random
    ip = requests.get("https://api.ipify.org", proxies=proxies,
                      headers={"User-Agent": ua}, timeout=10).text
    return ip, ua

def rotate_ip_loop(ui_callback):
    global stop_rotation
    while not stop_rotation:
        try:
            sock_user = f"u{random.randint(1, 1_000_000)}"
            ip, ua = tor_ip(sock_user)
            is_new = ip_history.check(ip)
            ui_callback(ip, ua, is_new)
        except Exception as e:
            ui_callback("Eroare", str(e), False)
        time.sleep(10)

# ------------------------ CSV ANONYMIZER OPTIMIZAT -------------------------

REGEXES = {
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I),
    "ip": re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|:[0-9a-f]*:", re.I),
    "cnp": re.compile(r"\b\d{13}\b"),
    "card": re.compile(r"(?:\d[ -]*?){13,19}"),
    "iban": re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}"),
    "phone": re.compile(r"\+?\d[\d\s\-]{5,}\d"),
    "date": re.compile(r"\d{4}-\d{1,2}-\d{1,2}"),
    "age": re.compile(r"^(1[0-1]\d|\d?\d)$"),
}

#hashing si mascare cu X-uri pentru continutul personal
sha = lambda t: hashlib.sha256(t.encode()).hexdigest()[:12]
mask4 = lambda d: "X" * (len(d) - 4) + d[-4:]

#Se ascunde ultimul segment al IP-ului
def mask_ip(val: str):
    try:
        ip = ipaddress.ip_address(val)
        return '.'.join(val.split('.')[:3] + ['0']) if ip.version == 4 else val
    except ValueError:
        return val

#transforma data intr-un deceniu generalizat
def mask_date(val: str):
    try:
        y = parse_date(val).year
        decade = (2025 - y) // 10 * 10
        return f"{decade}s"
    except:
        return val

def mask_age(val: str):
    try:
        age = int(val)
        return f"{(age // 10) * 10}s"
    except:
        return val

#Se mapeaza tipul detectat cu functia de anonimizare
ANON_BY_TYPE = {
    "email": sha,
    "ip": mask_ip,
    "cnp": lambda v: "X" * 11 + v[-2:],
    "card": mask4,
    "iban": lambda v: v[:4] + "X" * (len(v) - 8) + v[-4:],
    "phone": lambda v: "X" * (len(re.sub(r"\D", "", v)) - 2) + re.sub(r"\D", "", v)[-2:],
    "date": mask_date,
    "age": mask_age,
}

#se verifica fiecare valoare si identifica daca e de tip sensibil
def detect_value_type(text: str):
    for t, rx in REGEXES.items():
        if rx.fullmatch(text):
            return t
    return None

#se aplica mascarea pe toate celulele din dataset prin vectorizare
def anonymize_chunk(df: pd.DataFrame):
    for col in df.columns:
        df[col] = df[col].astype(str).apply(lambda v: ANON_BY_TYPE.get(detect_value_type(v), lambda x: x)(v))
    return df

# ------------------------------- INTERFATA GUI ------------------------------

from PIL import Image, ImageTk

class AnimatedGIF(tk.Label):
    def __init__(self, master, path, size=(150, 150), delay=100):
        self.frames = []
        self.delay = delay
        self.index = 0
        self.running = False

        # Încarcă toate cadrele GIF-ului și le redimensionează
        pil_img = Image.open(path)
        try:
            while True:
                frame = pil_img.copy().resize(size, Image.Resampling.LANCZOS)
                self.frames.append(ImageTk.PhotoImage(frame))
                pil_img.seek(len(self.frames))  # următorul frame
        except EOFError:
            pass

        if not self.frames:
            raise ValueError("GIF-ul nu conține cadre valide.")

        super().__init__(master, image=self.frames[0])

    def start(self):
        if not self.running:
            self.running = True
            self._animate()

    def stop(self):
        self.running = False

    def _animate(self):
        if self.running and self.frames:
            self.config(image=self.frames[self.index])
            self.index = (self.index + 1) % len(self.frames)
            self.after(self.delay, self._animate)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("IP + CSV Anonymizer")
        self.root.geometry("720x540")
        self.create_widgets()
        self.current_ip = None  # stocat după fiecare rotație

    def create_widgets(self):
        tabs = ttk.Notebook(self.root)
        self.tab_ip = ttk.Frame(tabs)
        self.tab_csv = ttk.Frame(tabs)
        tabs.add(self.tab_ip, text="IP Rotator")
        tabs.add(self.tab_csv, text="CSV Anonymizer")
        tabs.pack(expand=1, fill="both")

        # IP TAB
        self.ip_label = ttk.Label(self.tab_ip, text="Tor IP: ---", font=("Courier", 12))
        self.ua_label = ttk.Label(self.tab_ip, text="User-Agent: ---", wraplength=680)
        self.status_label = ttk.Label(self.tab_ip, text="Status: ---", foreground="gray")

        self.country_var = tk.StringVar(value="")
        self.country_menu = ttk.Combobox(self.tab_ip, textvariable=self.country_var, values=["", "DE", "US", "FR", "NL", "GB"], width=10)
        self.country_menu.set("Select Country")
        self.country_menu.bind("<<ComboboxSelected>>", self.set_country)

        self.ip_label.pack(pady=10)
        self.ua_label.pack(pady=5)
        self.status_label.pack(pady=5)
        self.country_menu.pack(pady=5)

        ttk.Button(self.tab_ip, text="Start Rotation", command=self.start_rotation).pack(pady=5)
        ttk.Button(self.tab_ip, text="Stop Rotation", command=self.stop_rotation_func).pack(pady=5)
        ttk.Button(self.tab_ip, text="Verify IP online", command=self.verify_ip_online).pack(pady=5)
        # GIF banner pentru IP Rotator
        self.banner_gif = AnimatedGIF(self.tab_ip, "C:\\Users\\test\\Desktop\\FolderTesteAplicatiiPython\\loading.gif")  # numele fișierului tău
        self.banner_gif.pack(pady=10)
        self.banner_gif.pack_forget()

        # CSV TAB
        self.csv_path = tk.StringVar()
        ttk.Button(self.tab_csv, text="Select CSV", command=self.select_csv).pack(pady=10)
        self.path_label = ttk.Label(self.tab_csv, textvariable=self.csv_path, wraplength=650)
        self.path_label.pack()

        ttk.Button(self.tab_csv, text="Anonymize & Save", command=self.run_csv_anonymization).pack(pady=10)
        self.log_box = scrolledtext.ScrolledText(self.tab_csv, height=15)
        self.log_box.pack(fill="both", expand=True)

    def update_ip_ui(self, ip, ua, is_new):
        self.current_ip = ip  # salvăm IP-ul curent
        self.ip_label.config(text=f"Tor IP: {ip}")
        self.ua_label.config(text=f"User-Agent: {ua}")
        self.status_label.config(
            text="Status: New IP" if is_new else "Status: Duplicate IP",
            foreground="green" if is_new else "red"
        )

    def start_rotation(self):
        global stop_rotation
        stop_rotation = False
        self.banner_gif.pack(pady=10)
        self.banner_gif.start()
        threading.Thread(target=rotate_ip_loop, args=(self.update_ip_ui,), daemon=True).start()

    def stop_rotation_func(self):
        global stop_rotation
        stop_rotation = True
        self.banner_gif.stop()
        self.banner_gif.pack_forget()  # Ascunde GIF-ul
        self.status_label.config(text="Status: Rotation Stopped", foreground="gray")

    def set_country(self, event=None):
        country = self.country_var.get()
        result = set_tor_exit_country(country)
        if result is True:
            messagebox.showinfo("Exit Node", f"Tor set to use country: {country}")
        else:
            messagebox.showerror("Error", f"Failed to set country: {result}")

    def select_csv(self):
        path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if path:
            self.csv_path.set(path)

    def run_csv_anonymization(self):
        path = self.csv_path.get()
        if not path:
            messagebox.showerror("Error", "Select a CSV file.")
            return
        threading.Thread(target=self._anonymize_csv_file, args=(path,), daemon=True).start()

    def _anonymize_csv_file(self, path):
        try:
            # Dezactivăm butoanele pe perioada procesării
            for widget in self.tab_csv.winfo_children():
                if isinstance(widget, ttk.Button):
                    widget.config(state="disabled")

            start_time = time.time()  # start timer
            out_path = Path(path).with_stem(Path(path).stem + "_anon.csv")

            self.log_box.insert(tk.END, "⏳ CSV file is being proccessed, this may take a while...\n")
            self.log_box.see(tk.END)

            dot_states = ["", ".", "..", "..."]
            dot_index = 0

            with open(out_path, "w", encoding="utf-8", newline='') as f_out:
                for i, chunk in enumerate(pd.read_csv(path, chunksize=100_000, dtype=str, keep_default_na=False)):
                    anon = anonymize_chunk(chunk)
                    anon.to_csv(f_out, index=False, header=i == 0)

                    dots = dot_states[dot_index % len(dot_states)]
                    dot_index += 1
                    self.log_box.insert(tk.END, f"   {dots}\n")
                    self.log_box.see(tk.END)

            duration = time.time() - start_time
            self.log_box.insert(tk.END, f"✔️ CSV saved → {out_path}\n")
            self.log_box.insert(tk.END, f"⏱️ Estimated time : {duration:.2f} seconds\n")
            self.log_box.see(tk.END)

        except Exception as e:
            self.log_box.insert(tk.END, f"❌ Eroare: {e}\n")
            self.log_box.see(tk.END)

        finally:
        # Reactivăm butoanele după procesare
            for widget in self.tab_csv.winfo_children():
                if isinstance(widget, ttk.Button):
                    widget.config(state="normal")
    
    def verify_ip_online(self):
        if self.current_ip:
            url = f"https://whatismyipaddress.com/ip/{self.current_ip}"
            webbrowser.open(url)
        else:
            messagebox.showwarning("IP Indisponibil", "IP-ul nu este încă disponibil.")


root = tk.Tk()
app = App(root)
root.mainloop()
