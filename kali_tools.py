#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import os
import re
import platform
from datetime import datetime
from urllib.parse import urlparse, urljoin
import webbrowser
import requests
from bs4 import BeautifulSoup


# ================================================================== #
#  TÜRKÇE AÇIKLAMA VERİTABANI
#  Her kayıt: (baslik, aciklama, risk, nasil_kullanilir, cozum)
# ================================================================== #
VULN_DB = {
    # ---------- SQL Injection ----------
    "sql": (
        "SQL Injection (SQL Enjeksiyonu)",
        "Saldırgan, web uygulamasının veritabanı sorgularına kötü amaçlı SQL kodu ekleyerek "
        "veritabanını manipüle edebilir. Kullanıcı girişleri doğrudan SQL sorgusuna dahil "
        "ediliyorsa bu açık oluşur.",
        "KRİTİK",
        "Saldırgan login formuna ' OR '1'='1 girerek kimlik doğrulamayı atlatabilir. "
        "Daha ileri aşamada tüm veritabanını dump edebilir, veri silebilir veya "
        "sunucuda komut çalıştırabilir (xp_cmdshell).",
        "Parametreli sorgular (prepared statements) kullanın. "
        "Kullanıcı girdilerini asla doğrudan sorguya eklemeyin. "
        "ORM kütüphanesi kullanın. Input validation uygulayın."
    ),
    "inject": (
        "Injection Açığı",
        "Kullanıcıdan alınan veriler doğrulanmadan sistem komutlarına, sorgu diline "
        "veya interpreter'a iletiliyor. SQL, OS Command, LDAP, XPath injection olabilir.",
        "KRİTİK",
        "Saldırgan özel karakterler göndererek backend sistemleri kontrol altına alabilir, "
        "veri çalabilir veya sistemi çökertebilir.",
        "Tüm kullanıcı girdilerini doğrulayın ve encode edin. "
        "En az yetki prensibini uygulayın. WAF kullanın."
    ),
    # ---------- XSS ----------
    "xss": (
        "Cross-Site Scripting (XSS)",
        "Saldırgan, web sayfasına kötü amaçlı JavaScript kodu enjekte eder. "
        "Bu kod diğer kullanıcıların tarayıcısında çalışır.",
        "YÜKSEK",
        "Saldırgan, kurbanın oturum çerezlerini çalabilir (session hijacking), "
        "sahte form göstererek kimlik bilgilerini ele geçirebilir veya "
        "kullanıcıyı zararlı siteye yönlendirebilir.",
        "Tüm çıktıları HTML encode edin. Content Security Policy (CSP) başlığı ekleyin. "
        "HttpOnly ve Secure flag'li cookie kullanın. Input validation uygulayın."
    ),
    # ---------- CSRF ----------
    "csrf": (
        "Cross-Site Request Forgery (CSRF)",
        "Saldırgan, oturum açmış bir kullanıcının haberi olmadan onun adına "
        "işlem yaptırır. Kurban zararlı bir bağlantıya tıkladığında gerçekleşir.",
        "ORTA",
        "Kullanıcı bankacılık sitesinde oturum açıkken zararlı sayfayı ziyaret ederse, "
        "saldırgan kullanıcı adına para transferi başlatabilir.",
        "CSRF token kullanın. SameSite cookie politikası uygulayın. "
        "Kritik işlemler için ek doğrulama isteyin."
    ),
    # ---------- Directory Traversal ----------
    "traversal": (
        "Directory Traversal (Dizin Geçişi)",
        "Saldırgan ../ karakterleri kullanarak web kök dizininin dışındaki "
        "dosyalara erişebilir.",
        "YÜKSEK",
        "Saldırgan /etc/passwd, /etc/shadow, uygulama kaynak kodları veya "
        "konfigürasyon dosyalarını okuyabilir.",
        "Dosya yollarını validate edin. Canonical path kontrolü yapın. "
        "Chroot jail veya konteyner kullanın."
    ),
    # ---------- Remote Code Execution ----------
    "rce": (
        "Remote Code Execution (Uzaktan Kod Çalıştırma)",
        "En tehlikeli açık türü. Saldırgan sunucu üzerinde istediği komutu çalıştırabilir.",
        "KRİTİK",
        "Saldırgan reverse shell açarak sunucuyu tamamen ele geçirebilir, "
        "fidye yazılımı yükleyebilir veya diğer sistemlere sıçrayabilir.",
        "Tüm yazılımları güncel tutun. Input validation uygulayın. "
        "Least privilege prensibini uygulayın. WAF ve IDS kullanın."
    ),
    "shell": (
        "Shell Erişimi / Webshell",
        "Sunucu üzerinde shell erişimi sağlanmış olabilir. "
        "Dosya yükleme açığı veya RCE aracılığıyla gerçekleşebilir.",
        "KRİTİK",
        "Saldırgan sunucuya tam erişim kazanmış olabilir. "
        "Tüm veriler risk altındadır.",
        "Sistem loglarını inceleyin. Şüpheli dosyaları temizleyin. "
        "Tüm şifreleri değiştirin. Güvenlik açığını kapatın."
    ),
    # ---------- Açık Dizin / Dosya ----------
    "admin": (
        "Admin Panel Erişimi",
        "Yönetim paneli internetten erişilebilir durumda. "
        "Brute force veya default şifrelerle giriş yapılabilir.",
        "YÜKSEK",
        "Saldırgan admin paneline erişerek siteyi tamamen ele geçirebilir, "
        "içerik değiştirebilir veya arka kapı yükleyebilir.",
        "Admin panelini IP kısıtlamasına alın. "
        "Güçlü şifre ve 2FA kullanın. URL'yi tahmin edilemez yapın."
    ),
    "backup": (
        "Backup Dosyası Tespit Edildi",
        "Yedek dosyalar (.bak, .old, .zip, .tar.gz) web sunucusunda erişilebilir. "
        "Kaynak kod veya hassas veri içerebilir.",
        "YÜKSEK",
        "Saldırgan veritabanı şifrelerini, API anahtarlarını veya kaynak kodunu "
        "indirerek daha büyük saldırılar planlayabilir.",
        "Yedek dosyaları web dizininde tutmayın. "
        ".htaccess ile hassas uzantıları engelleyin."
    ),
    "config": (
        "Konfigürasyon Dosyası İfşası",
        "Konfigürasyon dosyası (config.php, web.config, .env vb.) "
        "internetten erişilebilir.",
        "KRİTİK",
        "Veritabanı şifreleri, API anahtarları, gizli tokenlar ele geçirilebilir.",
        "Konfigürasyon dosyalarını web kök dizininin dışına taşıyın. "
        ".htaccess ile erişimi engelleyin."
    ),
    "password": (
        "Şifre İfşası / Zayıf Kimlik Doğrulama",
        "Şifreler veya kimlik bilgileri açık/zayıf biçimde bulundu.",
        "KRİTİK",
        "Saldırgan sistemlere yetkisiz erişim sağlayabilir.",
        "Güçlü şifre politikası uygulayın. Şifreleri hash'leyin (bcrypt/argon2). "
        "2FA kullanın. Default şifreleri değiştirin."
    ),
    "login": (
        "Login Sayfası Tespit Edildi",
        "Giriş sayfası bulundu. Brute force saldırısına açık olabilir.",
        "ORTA",
        "Saldırgan kullanıcı adı/şifre kombinasyonlarını deneyerek erişim sağlayabilir.",
        "Rate limiting uygulayın. Account lockout ekleyin. "
        "CAPTCHA kullanın. 2FA zorunlu kılın."
    ),
    # ---------- Header güvenlik sorunları ----------
    "x-frame": (
        "X-Frame-Options Eksik veya Hatalı",
        "Sayfa iframe içinde gösterilebilir. Clickjacking saldırısına açık.",
        "ORTA",
        "Saldırgan sayfanızı görünmez iframe içinde göstererek "
        "kullanıcının farkında olmadan tıklamasını sağlayabilir.",
        "X-Frame-Options: DENY veya SAMEORIGIN başlığı ekleyin. "
        "Content-Security-Policy frame-ancestors direktifi kullanın."
    ),
    "x-xss": (
        "XSS Koruma Başlığı",
        "X-XSS-Protection başlığı ile ilgili bir durum tespit edildi.",
        "DÜŞÜK",
        "Eski tarayıcılarda XSS koruması devre dışı kalabilir.",
        "X-XSS-Protection: 1; mode=block başlığını ekleyin. "
        "Modern tarayıcılar için Content-Security-Policy kullanın."
    ),
    "header": (
        "Güvenlik Başlığı Sorunu",
        "HTTP güvenlik başlıklarından biri eksik veya yanlış yapılandırılmış.",
        "DÜŞÜK",
        "Eksik başlıklar çeşitli client-side saldırılara zemin hazırlayabilir.",
        "Strict-Transport-Security, X-Content-Type-Options, "
        "X-Frame-Options, Content-Security-Policy başlıklarını ekleyin."
    ),
    "server": (
        "Sunucu Bilgisi İfşası",
        "HTTP yanıtları sunucu yazılımı ve versiyonunu açık ediyor. "
        "Bu bilgi saldırıları kolaylaştırır.",
        "DÜŞÜK",
        "Saldırgan sunucu versiyonunu öğrenerek bilinen CVE açıklarını hedefleyebilir.",
        "Server başlığını gizleyin veya genericleştirin. "
        "X-Powered-By başlığını kaldırın."
    ),
    "version": (
        "Eski/Güncellenmemiş Yazılım Versiyonu",
        "Kullanılan yazılımın bilinen güvenlik açığı olan eski bir versiyonu tespit edildi.",
        "YÜKSEK",
        "Saldırgan CVE veritabanlarından bu versiyona ait exploit'leri kullanabilir.",
        "Tüm yazılımları en güncel kararlı versiyona güncelleyin. "
        "Otomatik güncelleme mekanizması kurun."
    ),
    # ---------- SSL / TLS ----------
    "ssl": (
        "SSL/TLS Güvenlik Sorunu",
        "SSL/TLS yapılandırmasında zayıflık tespit edildi. "
        "Eski protokol versiyonu veya zayıf cipher suite olabilir.",
        "ORTA",
        "Saldırgan man-in-the-middle saldırısıyla iletişimi dinleyebilir veya değiştirebilir.",
        "TLS 1.2 ve 1.3 kullanın. Eski SSL/TLS versiyonlarını devre dışı bırakın. "
        "Güçlü cipher suite kullanın."
    ),
    "tls": (
        "TLS Yapılandırma Sorunu",
        "TLS sertifikası veya yapılandırmasında sorun tespit edildi.",
        "ORTA",
        "Güvenli kanal kurulumunu tehlikeye atabilir.",
        "Sertifikanızı güncel tutun. TLS 1.3 kullanın. "
        "HSTS başlığı ekleyin."
    ),
    # ---------- Open Port / Servis ----------
    "open": (
        "Açık Port Tespit Edildi",
        "Bu port internetten erişilebilir durumda ve bir servis çalışıyor.",
        "BİLGİ",
        "Gereksiz açık portlar saldırı yüzeyini genişletir. "
        "Servis versiyonu bilinen bir açık içeriyorsa exploit edilebilir.",
        "Sadece gerekli portları açık tutun. Güvenlik duvarı kurallarını gözden geçirin. "
        "Servisleri güncel tutun."
    ),
    "ftp": (
        "FTP Servisi Açık",
        "FTP servisi çalışıyor. FTP, şifresiz veri iletimi yapar.",
        "YÜKSEK",
        "Saldırgan ağı dinleyerek FTP kimlik bilgilerini ele geçirebilir. "
        "Anonymous FTP aktifse dosyalara erişebilir.",
        "FTP yerine SFTP veya FTPS kullanın. "
        "Anonymous girişi devre dışı bırakın. FTP'yi firewall ile kısıtlayın."
    ),
    "ssh": (
        "SSH Servisi Açık",
        "SSH servisi çalışıyor. Yapılandırma hatası varsa risk oluşturur.",
        "BİLGİ",
        "Zayıf şifre veya eski SSH versiyonu varsa brute force veya exploit mümkün.",
        "SSH key-based authentication kullanın. Root girişini kapatın. "
        "Fail2ban kurun. SSH versiyonunu güncel tutun."
    ),
    "telnet": (
        "Telnet Servisi Açık",
        "Telnet şifresiz iletişim yapar. Güvenli değildir.",
        "YÜKSEK",
        "Saldırgan ağ trafiğini dinleyerek kullanıcı adı ve şifreyi görebilir.",
        "Telnet'i tamamen kapatın. Yerine SSH kullanın."
    ),
    "rdp": (
        "RDP (Remote Desktop) Açık",
        "Windows Remote Desktop servisi internetten erişilebilir.",
        "YÜKSEK",
        "Brute force saldırısı, BlueKeep gibi RDP açıklarının exploit edilmesi riski var.",
        "RDP'yi sadece VPN üzerinden erişilebilir yapın. "
        "NLA (Network Level Authentication) aktif edin. Güncel tutun."
    ),
    "smb": (
        "SMB Servisi Açık",
        "SMB (Samba/Windows File Sharing) servisi internetten erişilebilir.",
        "KRİTİK",
        "EternalBlue (MS17-010), WannaCry gibi kritik SMB açıkları var. "
        "Tüm dosya sistemine erişim sağlanabilir.",
        "SMB'yi internetten tamamen kapatın. Sadece yerel ağda kullanın. "
        "Tüm Windows güncellemelerini uygulayın."
    ),
    "mysql": (
        "MySQL Portu Açık",
        "MySQL veritabanı servisi internetten erişilebilir.",
        "KRİTİK",
        "Saldırgan doğrudan veritabanına bağlanmayı deneyebilir. "
        "Başarılı olursa tüm verileri çalabilir.",
        "MySQL'i sadece localhost'a bağlayın. "
        "Güvenlik duvarı ile dışarıdan erişimi engelleyin."
    ),
    # ---------- CVE / Exploit ----------
    "cve": (
        "Bilinen CVE Açığı Tespit Edildi",
        "Sistemde kayıt altına alınmış ve yaygın olarak bilinen bir güvenlik açığı var.",
        "KRİTİK",
        "CVE numarası ile internette hazır exploit araçları bulunabilir. "
        "Teknik bilgisi az bir saldırgan bile bu açığı kullanabilir.",
        "İlgili yazılımı hemen güncelleyin veya yamanın yayımlanmasını beklerken "
        "geçici önlemler alın (WAF kuralı, servis devre dışı bırakma)."
    ),
    "exploit": (
        "Exploit Edilebilir Açık",
        "Tespit edilen açık için hazır exploit araçları mevcut olabilir.",
        "KRİTİK",
        "Saldırgan Metasploit, ExploitDB veya benzer kaynaklardan "
        "hazır exploit kullanabilir.",
        "Açığı hemen kapatın veya geçici olarak servisi devre dışı bırakın. "
        "Sistem loglarını acilen inceleyin."
    ),
    "vuln": (
        "Güvenlik Açığı Tespit Edildi",
        "Nmap NSE script taraması bir güvenlik açığı tespit etti.",
        "YÜKSEK",
        "Açığın detaylarına göre farklı saldırı vektörleri mümkündür.",
        "Açığın detaylarını araştırın. İlgili yamaları uygulayın. "
        "Servisi güncel tutun."
    ),
    # ---------- Dizin / Dosya keşfi ----------
    "200": (
        "Erişilebilir Dizin/Dosya (200 OK)",
        "Bu URL'ye herkes erişebiliyor ve içerik dönüyor.",
        "BİLGİ",
        "Gizli olması gereken bir sayfa veya dosyaysa hassas bilgi ifşası olabilir. "
        "Admin paneli, yedek dosya, konfigürasyon dosyası olabilir.",
        "Gereksiz dosyaları web dizininden kaldırın. "
        "Hassas sayfaları authentication ile koruyun."
    ),
    "403": (
        "Erişim Engellendi (403 Forbidden)",
        "Bu URL mevcut ama şu an erişim engelleniyor. "
        "Bazı durumlarda bypass edilebilir.",
        "ORTA",
        "Saldırgan HTTP method değiştirme, özel header ekleme veya "
        "URL encoding ile 403 bypass deneyebilir.",
        "Yetkilendirmeyi uygulama katmanında da doğrulayın. "
        "Sadece sunucu konfigürasyonuna güvenmeyin."
    ),
    "401": (
        "Kimlik Doğrulama Gerekiyor (401 Unauthorized)",
        "Bu kaynak şifreyle korumalı. Brute force saldırısına açık olabilir.",
        "ORTA",
        "Saldırgan kullanıcı adı/şifre kombinasyonları deneyebilir.",
        "Rate limiting ve hesap kilitleme mekanizması ekleyin. "
        "Güçlü şifre politikası uygulayın."
    ),
    "301": (
        "Yönlendirme (301 Redirect)",
        "Bu URL başka bir adrese yönlendiriyor.",
        "DÜŞÜK",
        "Açık yönlendirme (open redirect) varsa phishing saldırısında kullanılabilir.",
        "Yönlendirme hedeflerini whitelist ile kontrol edin."
    ),
    # ---------- Genel ----------
    "allow": (
        "İzin Verilen HTTP Metodları",
        "Sunucu desteklediği HTTP metodlarını açıklıyor. "
        "PUT veya DELETE aktifse tehlikeli olabilir.",
        "ORTA",
        "PUT metodu aktifse saldırgan sunucuya dosya yükleyebilir. "
        "DELETE ile dosyalar silinebilir.",
        "Sadece gerekli HTTP metodlarına izin verin. "
        "PUT ve DELETE'yi devre dışı bırakın."
    ),
    "waf": (
        "WAF/IPS Tespit Edildi",
        "Hedef sistemde Web Application Firewall veya IPS var. "
        "Bazı istekler engellenmiş olabilir.",
        "BİLGİ",
        "WAF atlatma teknikleri (encoding, fragmentation) denenebilir.",
        "WAF kurallarını düzenli güncelleyin. WAF'a rağmen kod güvenliğini sağlayın."
    ),
    "cookie": (
        "Cookie Güvenlik Sorunu",
        "Oturum çerezleri güvenli şekilde yapılandırılmamış olabilir.",
        "ORTA",
        "HttpOnly flag yoksa JavaScript ile cookie çalınabilir. "
        "Secure flag yoksa HTTP üzerinden iletilir.",
        "Cookie'lere HttpOnly ve Secure flag ekleyin. "
        "SameSite=Strict veya Lax kullanın."
    ),
    "default": (
        "Güvenlik Bulgusu",
        "Tarama aracı bu satırda dikkat edilmesi gereken bir bulgu tespit etti.",
        "BİLGİ",
        "Detaylı analiz için ham rapor dosyasını incelemeniz önerilir.",
        "Bulguyu araştırın ve gerekirse uzman görüşü alın."
    ),
}


def lookup_vuln(text):
    """
    Verilen metni VULN_DB ile eslestir.
    Eslesen ilk kaydi dondur; hicbiri uymuyorsa 'default' dondur.
    """
    tl = text.lower()
    priority = [
        "cve", "rce", "shell", "sql", "inject", "xss", "csrf",
        "traversal", "exploit", "vuln", "smb", "rdp", "mysql",
        "telnet", "ftp", "backup", "config", "password", "admin",
        "waf", "cookie", "ssl", "tls", "x-frame", "x-xss",
        "server", "version", "header", "allow", "login",
        "open", "ssh", "200", "403", "401", "301",
    ]
    for key in priority:
        if key in tl:
            return VULN_DB[key]
    return VULN_DB["default"]


def risk_color(risk):
    return {
        "KRİTİK": "#fee2e2",
        "YÜKSEK": "#fef3c7",
        "ORTA":   "#eff6ff",
        "DÜŞÜK":  "#f0fdf4",
        "BİLGİ":  "#f9fafb",
    }.get(risk, "#f9fafb")


class DesktopHunter:
    def __init__(self, root):
        self.root = root
        self.root.title("DESKTOP AUTO-REPORT HUNTER")
        self.root.geometry("1650x1050")

        self.desktop_path = self.get_desktop_path()
        self.report_folder = None

        self.scan_results = {
            "nikto": [], "whatweb": [], "sqlmap": [],
            "gobuster": [], "nmap": [], "dirb": [], "wfuzz": [],
        }

        self.setup_desktop_gui()

    # ================================================================== #
    #  YARDIMCI
    # ================================================================== #

    def get_desktop_path(self):
        return os.path.join(os.path.expanduser("~"), "Desktop")

    def validate_url(self, url):
        try:
            r = urlparse(url)
            return all([r.scheme in ("http", "https"), r.netloc])
        except Exception:
            return False

    def strip_ansi(self, text):
        return re.sub(r'\x1b\[[0-9;]*m', '', text)

    def log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, "[" + timestamp + "] " + msg + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def log_section(self, title):
        self.log("-" * 55)
        self.log("  " + title)
        self.log("-" * 55)

    def get_host(self, url):
        return urlparse(url).netloc.split(":")[0]

    # ================================================================== #
    #  DETAY PANELİ  (satıra tıklanınca açılır)
    # ================================================================== #

    def _make_detail_panel(self, parent):
        """
        Treeview'in altına yerleştirilen detay metin kutusu.
        Bir satıra tıklandığında Türkçe açıklama gösterir.
        """
        frame = ttk.LabelFrame(parent, text="Bulgu Detayı — Satıra tıklayın", padding=8)
        frame.pack(fill="x", padx=4, pady=(4, 0))

        txt = tk.Text(frame, height=8, font=("Consolas", 10), wrap="word",
                      state="disabled", relief="flat")
        txt.pack(fill="both", expand=True)

        # Renk tag'leri
        txt.tag_configure("title",   font=("Arial", 11, "bold"), foreground="#1e3a8a")
        txt.tag_configure("risk_kr", background="#fee2e2", font=("Arial", 10, "bold"))
        txt.tag_configure("risk_yu", background="#fef3c7", font=("Arial", 10, "bold"))
        txt.tag_configure("risk_or", background="#eff6ff", font=("Arial", 10, "bold"))
        txt.tag_configure("risk_du", background="#f0fdf4", font=("Arial", 10, "bold"))
        txt.tag_configure("risk_bi", background="#f9fafb", font=("Arial", 10, "bold"))
        txt.tag_configure("label",   font=("Arial", 10, "bold"), foreground="#374151")
        txt.tag_configure("body",    font=("Arial", 10))
        return txt

    def _show_detail(self, detail_txt, row_text):
        """
        row_text: tiklanan satirdan alınan ham metin
        VULN_DB'den eslesen aciklamayi detail_txt kutusuna yazar.
        """
        title, aciklama, risk, nasil, cozum = lookup_vuln(row_text)

        risk_tag = {
            "KRİTİK": "risk_kr",
            "YÜKSEK": "risk_yu",
            "ORTA":   "risk_or",
            "DÜŞÜK":  "risk_du",
            "BİLGİ":  "risk_bi",
        }.get(risk, "risk_bi")

        detail_txt.config(state="normal")
        detail_txt.delete("1.0", tk.END)

        detail_txt.insert(tk.END, title + "\n", "title")
        detail_txt.insert(tk.END, "Risk Seviyesi: ", "label")
        detail_txt.insert(tk.END, " " + risk + " \n\n", risk_tag)

        detail_txt.insert(tk.END, "NEDIR?\n", "label")
        detail_txt.insert(tk.END, aciklama + "\n\n", "body")

        detail_txt.insert(tk.END, "NASIL KULLANILIR (Saldırgan Perspektifi)?\n", "label")
        detail_txt.insert(tk.END, nasil + "\n\n", "body")

        detail_txt.insert(tk.END, "ÇÖZÜM / ÖNLEM:\n", "label")
        detail_txt.insert(tk.END, cozum + "\n", "body")

        detail_txt.config(state="disabled")

    # ================================================================== #
    #  GUI
    # ================================================================== #

    def setup_desktop_gui(self):
        style = ttk.Style()
        style.theme_use("clam")

        ttk.Label(
            self.root,
            text="MASAÜSTÜNE OTOMATİK RAPOR OLUŞTURUCU",
            font=("Arial", 18, "bold"),
        ).pack(pady=12)

        input_frame = ttk.LabelFrame(self.root, text="Hedef Site", padding=12)
        input_frame.pack(fill="x", padx=40, pady=5)

        ttk.Label(input_frame, text="Site URL:", font=("Arial", 12)).grid(row=0, column=0, sticky="w")
        self.url_entry = ttk.Entry(input_frame, font=("Consolas", 12), width=75)
        self.url_entry.grid(row=0, column=1, padx=(10, 0), pady=6, sticky="ew")
        self.url_entry.insert(0, "http://example.com/")

        self.folder_label = ttk.Label(
            input_frame, text="Masaüstü/example.com_142530",
            font=("Consolas", 10), foreground="#ff6600",
        )
        self.folder_label.grid(row=1, column=0, columnspan=2, sticky="w")
        self.url_entry.bind("<KeyRelease>", self.update_folder_preview)
        input_frame.columnconfigure(1, weight=1)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="FULL SCAN BAŞLAT", command=self.start_desktop_scan).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="MASAÜSTÜNÜ AÇ",   command=self.open_desktop).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="HTML RAPORU AÇ",  command=self.open_report_html).pack(side="left", padx=8)

        self.progress = ttk.Progressbar(self.root, mode="determinate", length=1000)
        self.progress.pack(pady=6, padx=40, fill="x")

        self.status_var = tk.StringVar(value="Hazir - URL gir ve başlat!")
        ttk.Label(self.root, textvariable=self.status_var, font=("Arial", 11)).pack()

        content_frame = ttk.Frame(self.root)
        content_frame.pack(fill="both", expand=True, padx=40, pady=8)

        log_frame = ttk.LabelFrame(content_frame, text="Canli Tarama Logu", padding=8)
        log_frame.pack(side="left", fill="both", expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, font=("Consolas", 9), width=46)
        self.log_text.pack(fill="both", expand=True)

        results_frame = ttk.LabelFrame(content_frame, text="Özet Sonuçlar  (Satıra tıklayın → Türkçe açıklama)", padding=8)
        results_frame.pack(side="right", fill="both", expand=True, padx=(8, 0))

        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill="both", expand=True)

        self.tab_nmap     = self._make_result_tab("Nmap")
        self.tab_nikto    = self._make_result_tab("Nikto")
        self.tab_whatweb  = self._make_result_tab("WhatWeb")
        self.tab_sqlmap   = self._make_result_tab("SQLMap")
        self.tab_gobuster = self._make_result_tab("Gobuster")
        self.tab_dirb     = self._make_result_tab("Dirb")
        self.tab_wfuzz    = self._make_result_tab("Wfuzz")
        self.tab_crawl    = self._make_result_tab("Formlar")

        for tab, msg in [
            (self.tab_nmap,     "Nmap taramasi bekleniyor..."),
            (self.tab_nikto,    "Nikto taramasi bekleniyor..."),
            (self.tab_whatweb,  "WhatWeb tespiti bekleniyor..."),
            (self.tab_sqlmap,   "SQLMap testi bekleniyor..."),
            (self.tab_gobuster, "Gobuster taramasi bekleniyor..."),
            (self.tab_dirb,     "Dirb taramasi bekleniyor..."),
            (self.tab_wfuzz,    "Wfuzz taramasi bekleniyor..."),
            (self.tab_crawl,    "Form taramasi bekleniyor..."),
        ]:
            self._set_placeholder(tab, msg)

    def _make_result_tab(self, title):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        return frame

    def _clear_tab(self, tab):
        for w in tab.winfo_children():
            w.destroy()

    def _set_placeholder(self, tab, msg):
        self._clear_tab(tab)
        ttk.Label(tab, text=msg, font=("Arial", 10), foreground="#9ca3af").pack(pady=30)

    def _make_tree_with_detail(self, tab, columns, col_widths):
        """
        Tab icine:
          - Usttte: scrollbarli Treeview
          - Altta: detay metin kutusu
        Treeview'e tiklayinca detay kutusuna Turkce aciklama yazilir.
        """
        self._clear_tab(tab)

        # Ust: tree container
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True)

        vsb  = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb  = ttk.Scrollbar(tree_frame, orient="horizontal")
        tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        for col, w in zip(columns, col_widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, minwidth=40)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)

        # Alt: detay kutusu
        detail_txt = self._make_detail_panel(tab)

        # Tiklama handler
        def on_click(event, t=tree, d=detail_txt):
            sel = t.selection()
            if not sel:
                return
            vals = t.item(sel[0], "values")
            combined = " ".join(str(v) for v in vals)
            self._show_detail(d, combined)

        tree.bind("<<TreeviewSelect>>", on_click)
        return tree

    def _make_tree(self, parent, columns, col_widths):
        """Sadece treeview (crawl alt sekmelerinde kullanilir)."""
        vsb  = ttk.Scrollbar(parent, orient="vertical")
        hsb  = ttk.Scrollbar(parent, orient="horizontal")
        tree = ttk.Treeview(
            parent, columns=columns, show="headings",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        for col, w in zip(columns, col_widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, minwidth=40)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        return tree

    # ================================================================== #
    #  SEKME YENİLEME
    # ================================================================== #

    def _refresh_nmap_tab(self, items):
        tree = self._make_tree_with_detail(
            self.tab_nmap,
            columns=["Port", "Durum", "Servis", "Versiyon", "Detay"],
            col_widths=[70, 70, 100, 130, 300],
        )
        color_map = {
            "open": "#f0fdf4", "filtered": "#fef3c7",
            "closed": "#f9fafb", "VULN": "#fee2e2",
        }
        for item in items:
            s  = item.get("state", "")
            bg = color_map.get(s, "#f9fafb")
            tree.insert("", "end",
                values=(item.get("port",""), s, item.get("service",""),
                        item.get("version",""), item.get("detail","")),
                tags=(s,))
            tree.tag_configure(s, background=bg)
        open_c = sum(1 for i in items if i.get("state") == "open")
        ttk.Label(self.tab_nmap,
            text=str(len(items)) + " satir  |  " + str(open_c) + " acik port  — Satıra tıklayın",
            font=("Consolas", 9), foreground="#374151").pack(pady=2)

    def _refresh_nikto_tab(self, items):
        tree = self._make_tree_with_detail(
            self.tab_nikto,
            columns=["Seviye", "Bulgu"],
            col_widths=[80, 580],
        )
        color_map = {"HIGH": "#fee2e2", "MED": "#fef3c7", "LOW": "#eff6ff", "INFO": "#f9fafb"}
        for item in items:
            sev = item["severity"]
            bg  = color_map.get(sev, "#f9fafb")
            tree.insert("", "end", values=(sev, item["msg"]), tags=(sev,))
            tree.tag_configure(sev, background=bg)
        counts  = {}
        for item in items:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        summary = "  ".join(k + ": " + str(v) for k, v in counts.items())
        ttk.Label(self.tab_nikto,
            text=str(len(items)) + " bulgu  |  " + summary + "  — Satıra tıklayın",
            font=("Consolas", 9), foreground="#374151").pack(pady=2)

    def _refresh_whatweb_tab(self, items):
        tree = self._make_tree_with_detail(
            self.tab_whatweb,
            columns=["E", "Bilesen", "Kategori", "Aciklama", "Deger"],
            col_widths=[25, 150, 110, 280, 130],
        )
        for item in items:
            tag = "sec" if "OK" in item["category"] else "other"
            tree.insert("", "end",
                values=(item["emoji"], item["key"], item["category"],
                        item["description"], item["value"]),
                tags=(tag,))
        tree.tag_configure("sec",   background="#f0fdf4")
        tree.tag_configure("other", background="#ffffff")
        ttk.Label(self.tab_whatweb,
            text=str(len(items)) + " bilesen  — Satıra tıklayın",
            font=("Consolas", 9), foreground="#374151").pack(pady=2)

    def _refresh_sqlmap_tab(self, items):
        tree = self._make_tree_with_detail(
            self.tab_sqlmap,
            columns=["Tur", "Bilgi"],
            col_widths=[110, 560],
        )
        color_map = {
            "ACIL": "#fee2e2", "VERI": "#fef3c7",
            "BILGI": "#eff6ff", "TEMIZ": "#f0fdf4",
        }
        for item in items:
            t  = item["type"]
            bg = color_map.get(t, "#f9fafb")
            tree.insert("", "end", values=(t, item["msg"]), tags=(t,))
            tree.tag_configure(t, background=bg)
        ttk.Label(self.tab_sqlmap,
            text=str(len(items)) + " sonuc  — Satıra tıklayın",
            font=("Consolas", 9), foreground="#374151").pack(pady=2)

    def _refresh_gobuster_tab(self, items):
        tree = self._make_tree_with_detail(
            self.tab_gobuster,
            columns=["Durum", "Yol", "Boyut"],
            col_widths=[70, 390, 80],
        )
        color_map = {
            "200": "#f0fdf4", "301": "#eff6ff", "302": "#eff6ff",
            "403": "#fef3c7", "401": "#fef3c7", "500": "#fee2e2",
        }
        for item in items:
            s  = item["status"]
            bg = color_map.get(s, "#f9fafb")
            tree.insert("", "end", values=(s, item["path"], item.get("size","")), tags=(s,))
            tree.tag_configure(s, background=bg)
        ttk.Label(self.tab_gobuster,
            text=str(len(items)) + " dizin  — Satıra tıklayın",
            font=("Consolas", 9), foreground="#374151").pack(pady=2)

    def _refresh_dirb_tab(self, items):
        tree = self._make_tree_with_detail(
            self.tab_dirb,
            columns=["Durum", "URL", "Boyut"],
            col_widths=[70, 430, 80],
        )
        color_map = {
            "200": "#f0fdf4", "301": "#eff6ff", "302": "#eff6ff",
            "403": "#fef3c7", "401": "#fef3c7", "500": "#fee2e2",
        }
        for item in items:
            s  = item["status"]
            bg = color_map.get(s, "#f9fafb")
            tree.insert("", "end", values=(s, item["url"], item.get("size","")), tags=(s,))
            tree.tag_configure(s, background=bg)
        ttk.Label(self.tab_dirb,
            text=str(len(items)) + " dizin  — Satıra tıklayın",
            font=("Consolas", 9), foreground="#374151").pack(pady=2)

    def _refresh_wfuzz_tab(self, items):
        tree = self._make_tree_with_detail(
            self.tab_wfuzz,
            columns=["Durum", "Kelime", "Satir", "Karakter", "URL"],
            col_widths=[65, 75, 65, 75, 380],
        )
        color_map = {
            "200": "#f0fdf4", "301": "#eff6ff", "302": "#eff6ff",
            "403": "#fef3c7", "401": "#fef3c7", "500": "#fee2e2",
        }
        for item in items:
            s  = item["status"]
            bg = color_map.get(s, "#f9fafb")
            tree.insert("", "end",
                values=(s, item.get("words",""), item.get("lines",""),
                        item.get("chars",""), item.get("url","")),
                tags=(s,))
            tree.tag_configure(s, background=bg)
        ttk.Label(self.tab_wfuzz,
            text=str(len(items)) + " sonuc  — Satıra tıklayın",
            font=("Consolas", 9), foreground="#374151").pack(pady=2)

    def _refresh_crawl_tab(self, crawl_data):
        self._clear_tab(self.tab_crawl)
        nb2 = ttk.Notebook(self.tab_crawl)
        nb2.pack(fill="both", expand=True)

        form_frame = ttk.Frame(nb2)
        nb2.add(form_frame, text="Formlar (" + str(len(crawl_data["forms"])) + ")")
        tree_f = self._make_tree(form_frame,
            columns=["Metod", "URL", "Parametreler"],
            col_widths=[60, 300, 300])
        for frm in crawl_data["forms"]:
            bg  = "#fee2e2" if frm["method"] == "post" else "#eff6ff"
            tag = frm["method"]
            tree_f.insert("", "end",
                values=(frm["method"].upper(), frm["url"], ", ".join(frm["params"])),
                tags=(tag,))
            tree_f.tag_configure(tag, background=bg)

        param_frame = ttk.Frame(nb2)
        nb2.add(param_frame, text="Parametreli URL (" + str(len(crawl_data["params"])) + ")")
        tree_p = self._make_tree(param_frame, columns=["URL"], col_widths=[700])
        for p in crawl_data["params"]:
            tree_p.insert("", "end", values=(p,))

    # ================================================================== #
    #  KLASÖR YÖNETİMİ
    # ================================================================== #

    def update_folder_preview(self, event=None):
        url = self.url_entry.get().strip()
        if url:
            domain = urlparse(url).netloc.replace("www.", "") or "site"
            ts = datetime.now().strftime("%H%M%S")
            self.folder_label.config(text="Masaüstü/" + domain + "_" + ts)
        else:
            self.folder_label.config(text="URL gir...")

    def create_report_folder(self, url):
        domain      = urlparse(url).netloc.replace("www.", "") or "site"
        ts          = datetime.now().strftime("%H%M%S")
        folder_path = os.path.join(self.desktop_path, domain + "_" + ts)
        os.makedirs(folder_path, exist_ok=True)
        self.log("Klasör oluşturuldu: " + folder_path)
        return folder_path

    # ================================================================== #
    #  TARAMA BAŞLATMA
    # ================================================================== #

    def start_desktop_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Hata", "URL girin!")
            return
        if not self.validate_url(url):
            messagebox.showerror("Gecersiz URL", "Örnek: http://example.com")
            return
        for k in self.scan_results:
            self.scan_results[k] = []
        self.report_folder = self.create_report_folder(url)
        self.progress["value"] = 0
        self.status_var.set("Tarama baslatiliyor...")
        threading.Thread(target=self.run_full_scan, daemon=True).start()

    # ================================================================== #
    #  ARAÇ ÇALIŞTIRICI
    # ================================================================== #

    def run_tool(self, cmd, label, timeout=300):
        self.log(">> " + label + " baslatildi...")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0 and result.stderr:
                self.log("UYARI " + label + ": " + result.stderr[:200])
            else:
                self.log("OK " + label + " tamamlandi.")
            return result
        except subprocess.TimeoutExpired:
            self.log("TIMEOUT " + label + " (" + str(timeout // 60) + " dk).")
        except FileNotFoundError:
            self.log("HATA: " + label + " kurulu degil.")
        except Exception as e:
            self.log("HATA " + label + ": " + str(e))

    # ================================================================== #
    #  PARSER: NMAP
    # ================================================================== #

    def parse_nmap(self, path):
        results = []
        if not os.path.exists(path):
            return results
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        current_port = None
        for line in lines:
            line = line.rstrip()
            m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)", line)
            if m:
                current_port = {
                    "port":    m.group(1) + "/" + m.group(2),
                    "state":   m.group(3),
                    "service": m.group(4),
                    "version": m.group(5).strip()[:80],
                    "detail":  "",
                }
                results.append(current_port)
                continue
            if current_port and line.startswith("|"):
                dl = line.lstrip("| ").strip()[:120]
                if dl:
                    ll = dl.lower()
                    if any(k in ll for k in ["vuln", "cve-", "exploit", "vulnerable", "backdoor"]):
                        results.append({
                            "port":    current_port["port"],
                            "state":   "VULN",
                            "service": current_port["service"],
                            "version": "",
                            "detail":  dl,
                        })
                    else:
                        if current_port["detail"]:
                            current_port["detail"] += " | " + dl
                        else:
                            current_port["detail"] = dl
                        current_port["detail"] = current_port["detail"][:150]
        return results

    def log_nmap_results(self, items):
        self.log_section("NMAP PORT TARAMASI")
        if not items:
            self.log("  [!] Parse edilecek port satiri bulunamadi.")
            self.log("      Olasi sebepler:")
            self.log("      1) Hedef tum portlari kapali/filtreliyor")
            self.log("      2) SYN taramasi icin root gerekebilir:")
            self.log("         sudo python3 desktop_hunter.py")
            self.log("      3) nmap_report.txt dosyasini manuel inceleyin")
            return
        open_ports = [i for i in items if i.get("state") == "open"]
        vuln_ports = [i for i in items if i.get("state") == "VULN"]
        self.log("  Toplam: " + str(len(items)) + " port  |  Acik: " + str(len(open_ports)) + "  |  VULN: " + str(len(vuln_ports)))
        for item in items:
            state  = item.get("state", "")
            prefix = "[ACIK]" if state == "open" else ("[VULN]" if state == "VULN" else "[" + state.upper() + "]")
            detail = "  -> " + item["detail"] if item.get("detail") else ""
            self.log("  " + prefix + "  " + item.get("port","") + "  " + item.get("service","") + "  " + item.get("version","") + detail)

    # ================================================================== #
    #  PARSER: NİKTO
    # ================================================================== #

    def parse_nikto(self, path):
        results = []
        if not os.path.exists(path):
            return results
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                ll = line.lower()
                if any(k in ll for k in ["sql", "inject", "rce", "remote code", "shell"]):
                    sev = "HIGH"
                elif any(k in ll for k in ["xss", "csrf", "traversal", "vuln", "exploit"]):
                    sev = "HIGH"
                elif any(k in ll for k in ["password", "admin", "login", "config", "backup"]):
                    sev = "MED"
                elif any(k in ll for k in ["header", "server", "version", "allow"]):
                    sev = "LOW"
                else:
                    sev = "INFO"
                results.append({"severity": sev, "msg": line[:200]})
        return results

    def log_nikto_results(self, items):
        self.log_section("NIKTO BULGULARI")
        if not items:
            self.log("  Nikto ciktisi bos veya arac kurulu degil.")
            return
        icons = {"HIGH": "[KRITIK]", "MED": "[ORTA]", "LOW": "[DUSUK]", "INFO": "[BILGI]"}
        for item in items:
            self.log("  " + icons.get(item["severity"], "-") + "  " + item["msg"])

    # ================================================================== #
    #  PARSER: WHATWEB
    # ================================================================== #

    WHATWEB_META = {
        "ASP_NET":                   ("*", "Framework",   "ASP.NET - Microsoft web cercevesi"),
        "Bootstrap":                 ("*", "UI Lib",      "Bootstrap CSS framework"),
        "jQuery":                    ("*", "JS Lib",      "jQuery kutuphanesi"),
        "Cookies":                   ("*", "Cerezler",    "Oturum cerezleri"),
        "HttpOnly":                  ("+", "Guvenlik OK", "Cerezler JS ile okunamaz - iyi"),
        "Strict-Transport-Security": ("+", "Guvenlik OK", "Yalnizca HTTPS zorunlu - iyi"),
        "X-Frame-Options":           ("+", "Guvenlik OK", "Clickjacking korumasi aktif - iyi"),
        "X-XSS-Protection":          ("+", "Guvenlik OK", "XSS korumasi aktif - iyi"),
        "UncommonHeaders":           ("+", "Guvenlik OK", "Ek guvenlik basliklari mevcut"),
        "Country":                   ("*", "Konum",       "Sunucunun bulundugu ulke"),
        "IP":                        ("*", "Sunucu IP",   "Hedef sunucunun IP adresi"),
        "Title":                     ("*", "Sayfa",       "HTML title etiketi"),
        "HTML5":                     ("*", "Teknoloji",   "HTML5 kullaniliyor"),
        "PasswordField":             ("!", "Form",        "Sifre giris alanlari tespit edildi"),
        "X-UA-Compatible":           ("*", "Tarayici",    "IE uyumluluk modu"),
        "Script":                    ("*", "Script",      "Sayfa ici script turleri"),
        "x-content-type-options":    ("+", "Guvenlik OK", "MIME sniffing korumasi - iyi"),
        "referrer-policy":           ("+", "Guvenlik OK", "Referrer politikasi tanimli - iyi"),
    }

    def parse_whatweb_output(self, raw):
        clean   = self.strip_ansi(raw)
        results = []
        pattern = re.compile(r'([\w\-]+)(?:\[([^\]]*)\])?')
        for line in clean.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(" ", 1)
            if len(parts) < 2:
                continue
            for match in pattern.finditer(parts[1]):
                key   = match.group(1).strip()
                value = (match.group(2) or "").strip()
                if len(key) < 3 or key in ("OK", "HTTP", "and", "the"):
                    continue
                meta = self.WHATWEB_META.get(key, ("*", "Diger", key))
                results.append({"key": key, "value": value if value else "-",
                                 "emoji": meta[0], "category": meta[1], "description": meta[2]})
        seen, unique = set(), []
        for r in results:
            if r["key"] not in seen:
                seen.add(r["key"])
                unique.append(r)
        return unique

    def log_whatweb_results(self, items):
        self.log_section("WHATWEB TEKNOLOJI ANALIZI")
        for item in items:
            val = "  ->  " + item["value"] if item["value"] != "-" else ""
            self.log("  [" + item["emoji"] + "]  " + item["description"] + val)

    # ================================================================== #
    #  PARSER: SQLMAP
    # ================================================================== #

    def parse_sqlmap_results(self, sqlmap_folder):
        results    = []
        found_vuln = False
        if not os.path.isdir(sqlmap_folder):
            results.append({"type": "BILGI", "msg": "SQLMap cikti klasoru bulunamadi."})
            return results
        for root_dir, dirs, files in os.walk(sqlmap_folder):
            for fname in files:
                fpath = os.path.join(root_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                clean = self.strip_ansi(content)
                for m in re.finditer(
                    r"(parameter .+? is vulnerable|is vulnerable to .+?injection"
                    r"|found a total of \d+ injectable|sqlmap identified)",
                    clean, re.IGNORECASE):
                    found_vuln = True
                    results.append({"type": "ACIL", "msg": "ACIK BULUNDU: " + m.group().strip()[:150]})
                for m in re.finditer(r"(Type: .+|Payload: .+|Title: .+)", clean, re.IGNORECASE):
                    results.append({"type": "ACIL", "msg": m.group().strip()[:150]})
                for m in re.finditer(r"available databases.*?:\s*([\[\]*\w\s,'\-]+)", clean, re.IGNORECASE | re.DOTALL):
                    results.append({"type": "VERI", "msg": "Veritabanlari: " + m.group(1).strip()[:200]})
                for m in re.finditer(r"Database: (\w+).*?(\d+) tables?", clean, re.IGNORECASE | re.DOTALL):
                    results.append({"type": "VERI", "msg": "DB: " + m.group(1) + "  -  " + m.group(2) + " tablo"})
                for m in re.finditer(r"(fetched data logged to|table '[\w.]+' dumped)", clean, re.IGNORECASE):
                    results.append({"type": "VERI", "msg": "Veri cekildi: " + m.group().strip()[:150]})
                for m in re.finditer(r"(WAF/IPS|heuristic \(basic\) test|connection refused|429|rate limit)", clean, re.IGNORECASE):
                    results.append({"type": "BILGI", "msg": "WAF/Engel: " + m.group().strip()[:150]})
        if not found_vuln and not any(r["type"] in ("ACIL", "VERI") for r in results):
            results.append({"type": "TEMIZ", "msg": "SQL injection acigi tespit edilmedi."})
        seen, unique = set(), []
        for r in results:
            if r["msg"] not in seen:
                seen.add(r["msg"])
                unique.append(r)
        return unique

    def log_sqlmap_results(self, items):
        self.log_section("SQLMAP SONUCLARI")
        icons = {"ACIL": "[KRITIK]", "VERI": "[VERI]", "BILGI": "[BILGI]", "TEMIZ": "[TEMIZ]"}
        for item in items:
            self.log("  " + icons.get(item["type"], "-") + " " + item["msg"])

    # ================================================================== #
    #  PARSER: GOBUSTER
    # ================================================================== #

    def parse_gobuster(self, path):
        results = []
        if not os.path.exists(path):
            return results
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("="):
                    continue
                m = re.match(r"(.+?)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)
                if m:
                    results.append({"path": m.group(1).strip(), "status": m.group(2), "size": m.group(3) or ""})
                else:
                    results.append({"path": line[:200], "status": "???", "size": ""})
        return results

    def log_gobuster_results(self, items):
        self.log_section("GOBUSTER DIZIN KESFI")
        if not items:
            self.log("  Gobuster sonucu yok veya arac kurulu degil.")
            return
        for item in items:
            size = "  [" + item["size"] + " B]" if item["size"] else ""
            self.log("  [" + item["status"] + "]  " + item["path"] + size)

    # ================================================================== #
    #  PARSER: DIRB
    # ================================================================== #

    def parse_dirb(self, path):
        results = []
        if not os.path.exists(path):
            return results
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-") or line.startswith("="):
                    continue
                m = re.match(r"\+\s+(https?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)", line)
                if m:
                    results.append({"url": m.group(1), "status": m.group(2), "size": m.group(3)})
                elif line.startswith("+") and "http" in line:
                    url_m = re.search(r"(https?://\S+)", line)
                    cod_m = re.search(r"CODE:(\d+)", line)
                    siz_m = re.search(r"SIZE:(\d+)", line)
                    if url_m:
                        results.append({
                            "url":    url_m.group(1),
                            "status": cod_m.group(1) if cod_m else "???",
                            "size":   siz_m.group(1) if siz_m else "",
                        })
        return results

    def log_dirb_results(self, items):
        self.log_section("DIRB DIZIN KESFI")
        if not items:
            self.log("  Dirb sonucu yok veya arac kurulu degil.")
            return
        for item in items:
            size = "  [" + item.get("size","") + " B]" if item.get("size") else ""
            self.log("  [" + item["status"] + "]  " + item["url"] + size)

    # ================================================================== #
    #  PARSER: WFUZZ
    # ================================================================== #

    def parse_wfuzz(self, path):
        results = []
        if not os.path.exists(path):
            return results
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.lower().startswith("id"):
                    continue
                parts = line.split(",")
                if len(parts) >= 6:
                    status = parts[1].strip()
                    if status in ("000", ""):
                        continue
                    results.append({
                        "status": status,
                        "lines":  parts[2].strip(),
                        "words":  parts[3].strip(),
                        "chars":  parts[4].strip(),
                        "url":    parts[6].strip() if len(parts) > 6 else parts[5].strip(),
                    })
                else:
                    m = re.match(r"\d+:\s+C=(\d+)\s+(\d+)\s+L\s+(\d+)\s+W\s+(\d+)\s+Ch\s+\"?(\S+)\"?", line)
                    if m:
                        results.append({"status": m.group(1), "lines": m.group(2),
                                        "words": m.group(3), "chars": m.group(4), "url": m.group(5)})
        return results

    def log_wfuzz_results(self, items):
        self.log_section("WFUZZ SONUCLARI")
        if not items:
            self.log("  Wfuzz sonucu yok veya arac kurulu degil.")
            return
        for item in items:
            self.log("  [" + item["status"] + "]  " + item.get("url","") + "  (" + item.get("chars","?") + " ch)")

    # ================================================================== #
    #  FORM & PARAMETRE TARAYICI
    # ================================================================== #

    def crawl_forms_and_params(self, base_url):
        self.log("Form & parametre tarayici baslatildi...")
        found   = {"forms": [], "params": []}
        visited = set()
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
        try:
            resp = requests.get(base_url, headers=headers, timeout=10, verify=False)
            resp.raise_for_status()
        except Exception as e:
            self.log("Ana sayfa cekilemedi: " + str(e))
            return found
        soup           = BeautifulSoup(resp.text, "html.parser")
        pages_to_visit = [base_url]
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if urlparse(href).netloc == urlparse(base_url).netloc and href not in visited:
                pages_to_visit.append(href)
                if len(pages_to_visit) >= 30:
                    break
        self.log("Taranacak sayfa: " + str(len(pages_to_visit)))
        for page_url in pages_to_visit:
            if page_url in visited:
                continue
            visited.add(page_url)
            try:
                r     = requests.get(page_url, headers=headers, timeout=8, verify=False)
                psoup = BeautifulSoup(r.text, "html.parser")
            except Exception:
                continue
            if urlparse(page_url).query and page_url not in found["params"]:
                found["params"].append(page_url)
                self.log("Parametreli URL: " + page_url)
            for form in psoup.find_all("form"):
                action   = form.get("action", "")
                method   = form.get("method", "get").lower()
                form_url = urljoin(page_url, action) if action else page_url
                inputs   = [inp.get("name") for inp in form.find_all(["input","textarea","select"]) if inp.get("name")]
                if inputs:
                    fd = {"url": form_url, "method": method, "params": inputs}
                    if fd not in found["forms"]:
                        found["forms"].append(fd)
                        self.log("Form: [" + method.upper() + "] " + form_url)
        self.log(str(len(found["forms"])) + " form, " + str(len(found["params"])) + " parametreli URL bulundu.")
        return found

    def build_sqlmap_targets(self, base_url, crawl_data):
        targets = []
        folder  = self.report_folder
        flags   = "--batch --risk=1 --level=1 --threads=10 --timeout=8 --retries=1 --smart --technique=BEUST --time-sec=3 "
        for p in crawl_data["params"]:
            targets.append(('sqlmap -u "' + p + '" ' + flags + '--output-dir="' + folder + '/sqlmap"',
                             "SQLMap GET -> " + p[:55]))
        for form in crawl_data["forms"]:
            form_url = form["url"]
            ps       = "&".join(x + "=1" for x in form["params"])
            if form["method"] == "post":
                targets.append(('sqlmap -u "' + form_url + '" --data="' + ps + '" ' + flags + '--output-dir="' + folder + '/sqlmap"',
                                 "SQLMap POST -> " + form_url[:55]))
            else:
                sep = "&" if "?" in form_url else "?"
                targets.append(('sqlmap -u "' + form_url + sep + ps + '" ' + flags + '--output-dir="' + folder + '/sqlmap"',
                                 "SQLMap FORM -> " + form_url[:55]))
        if not targets:
            self.log("Form/parametre yok -> SQLMap crawl modu")
            targets.append(('sqlmap -u "' + base_url + '" ' + flags + '--crawl=2 --output-dir="' + folder + '/sqlmap"',
                             "SQLMap (crawl modu)"))
        return targets

    # ================================================================== #
    #  ANA TARAMA AKIŞI
    # ================================================================== #

    def run_full_scan(self):
        try:
            url    = self.url_entry.get().strip()
            folder = self.report_folder
            host   = self.get_host(url)

            # 1. FORM & PARAMETRE
            self.progress["value"] = 3
            self.status_var.set("Form & parametre taranıyor...")
            crawl_data = self.crawl_forms_and_params(url)
            self.root.after(0, lambda cd=crawl_data: self._refresh_crawl_tab(cd))
            crawl_path = os.path.join(folder, "crawl_report.txt")
            with open(crawl_path, "w", encoding="utf-8") as f:
                f.write("Hedef: " + url + "\nTarih: " + str(datetime.now()) + "\n\n")
                for i, frm in enumerate(crawl_data["forms"], 1):
                    f.write(str(i) + ". " + frm["url"] + " [" + frm["method"].upper() + "] -> " + str(frm["params"]) + "\n")
                f.write("\n")
                for i, p in enumerate(crawl_data["params"], 1):
                    f.write(str(i) + ". " + p + "\n")

            # 2. NMAP
            self.progress["value"] = 10
            self.status_var.set("Nmap: port taramasi...")
            nmap_path = os.path.join(folder, "nmap_report.txt")

            # -sV: versiyon tespiti  -T4: hizli mod
            # NOT: -sC scripti ve -sS SYN taramasi root gerektirir
            # Burada root gerektirmeyen -sV -T4 kullaniliyor
            # Daha derin tarama icin terminalde: sudo nmap -sV -sC -T4 hedef
            nmap_result = self.run_tool(
                'nmap -sV -T4 -oN "' + nmap_path + '" ' + host,
                "Nmap", timeout=300,
            )

            # Ham ciktiyi loga yaz (debug)
            if os.path.exists(nmap_path):
                with open(nmap_path, "r", encoding="utf-8", errors="ignore") as nf:
                    raw_lines = nf.readlines()
                self.log("  [nmap] " + str(len(raw_lines)) + " satir cikti alindi.")
                for rl in raw_lines[:10]:
                    rl = rl.rstrip()
                    if rl and not rl.startswith("#"):
                        self.log("  " + rl)
            else:
                self.log("  [!] nmap_report.txt olusturulamadi.")
                if nmap_result and nmap_result.stdout:
                    with open(nmap_path, "w", encoding="utf-8") as nf:
                        nf.write(nmap_result.stdout)
                    self.log("  [i] Nmap stdout ciktisi kaydedildi.")

            nmap_items = self.parse_nmap(nmap_path)
            self.scan_results["nmap"] = nmap_items
            self.log_nmap_results(nmap_items)
            self.root.after(0, lambda ni=nmap_items: self._refresh_nmap_tab(ni))

            # 3. NİKTO
            self.progress["value"] = 20
            self.status_var.set("Nikto: sunucu taraması...")
            nikto_path = os.path.join(folder, "nikto_report.txt")
            self.run_tool('nikto -h "' + url + '" -Tuning 123bde -maxtime 120 -nointeractive -o "' + nikto_path + '"', "Nikto", timeout=150)
            nikto_items = self.parse_nikto(nikto_path)
            self.scan_results["nikto"] = nikto_items
            self.log_nikto_results(nikto_items)
            self.root.after(0, lambda nk=nikto_items: self._refresh_nikto_tab(nk))

            # 4. WHATWEB
            self.progress["value"] = 30
            self.status_var.set("WhatWeb: teknoloji tespiti...")
            ww_path = os.path.join(folder, "whatweb_report.txt")
            self.run_tool('whatweb -a 1 "' + url + '" > "' + ww_path + '" 2>&1', "WhatWeb", timeout=60)
            ww_items = []
            if os.path.exists(ww_path):
                with open(ww_path, "r", encoding="utf-8", errors="ignore") as f:
                    ww_items = self.parse_whatweb_output(f.read())
            self.scan_results["whatweb"] = ww_items
            self.log_whatweb_results(ww_items)
            self.root.after(0, lambda wi=ww_items: self._refresh_whatweb_tab(wi))

            # 5. SQLMAP
            self.progress["value"] = 40
            self.status_var.set("SQLMap çalışıyor...")
            targets = self.build_sqlmap_targets(url, crawl_data)
            self.log(str(len(targets)) + " SQLMap hedefi")
            for i, (cmd, label) in enumerate(targets):
                self.progress["value"] = 40 + int(13 * (i / max(len(targets), 1)))
                self.status_var.set("SQLMap: " + label)
                self.run_tool(cmd, label, timeout=180)
            sql_items = self.parse_sqlmap_results(os.path.join(folder, "sqlmap"))
            self.scan_results["sqlmap"] = sql_items
            self.log_sqlmap_results(sql_items)
            self.root.after(0, lambda si=sql_items: self._refresh_sqlmap_tab(si))

            # 6. GOBUSTER
            self.progress["value"] = 56
            self.status_var.set("Gobuster çalışıyor...")
            wordlists = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            ]
            wordlist = next((w for w in wordlists if os.path.exists(w)), None)
            gb_path  = os.path.join(folder, "gobuster.txt")
            if wordlist:
                self.run_tool('gobuster dir -u "' + url + '" -w "' + wordlist + '" -o "' + gb_path + '" -t 20 --timeout 5s -q', "Gobuster", timeout=300)
            else:
                self.log("Gobuster wordlist bulunamadi.")
            gb_items = self.parse_gobuster(gb_path)
            self.scan_results["gobuster"] = gb_items
            self.log_gobuster_results(gb_items)
            self.root.after(0, lambda gi=gb_items: self._refresh_gobuster_tab(gi))

            # 7. DIRB
            self.progress["value"] = 70
            self.status_var.set("Dirb çalışıyor...")
            dirb_path = os.path.join(folder, "dirb_report.txt")
            dirb_wl   = "/usr/share/wordlists/dirb/common.txt"
            if os.path.exists(dirb_wl):
                self.run_tool('dirb "' + url + '" "' + dirb_wl + '" -o "' + dirb_path + '" -S -r', "Dirb", timeout=240)
            else:
                self.log("Dirb wordlist bulunamadi.")
            dirb_items = self.parse_dirb(dirb_path)
            self.scan_results["dirb"] = dirb_items
            self.log_dirb_results(dirb_items)
            self.root.after(0, lambda di=dirb_items: self._refresh_dirb_tab(di))

            # 8. WFUZZ
            self.progress["value"] = 82
            self.status_var.set("Wfuzz çalışıyor...")
            wfuzz_path = os.path.join(folder, "wfuzz_report.csv")
            wfuzz_wl   = "/usr/share/wordlists/dirb/common.txt"
            if os.path.exists(wfuzz_wl):
                self.run_tool(
                    'wfuzz -c --hc 404 -t 20 -w "' + wfuzz_wl + '" '
                    '-f "' + wfuzz_path + '",csv "' + url.rstrip("/") + '/FUZZ"',
                    "Wfuzz", timeout=240)
            else:
                self.log("Wfuzz wordlist bulunamadi.")
            wfuzz_items = self.parse_wfuzz(wfuzz_path)
            self.scan_results["wfuzz"] = wfuzz_items
            self.log_wfuzz_results(wfuzz_items)
            self.root.after(0, lambda wfi=wfuzz_items: self._refresh_wfuzz_tab(wfi))

            # 9. HTML RAPOR
            self.progress["value"] = 93
            self.status_var.set("Rapor oluşturuluyor...")
            self.generate_desktop_report(url, crawl_data, ww_items, sql_items,
                                         nikto_items, gb_items, nmap_items, dirb_items, wfuzz_items)

            self.progress["value"] = 100
            self.status_var.set("Tarama tamamlandi!")
            self.log_section("TARAMA TAMAMLANDI")

        except Exception as e:
            self.log("Beklenmeyen hata: " + str(e))
            self.status_var.set("Hata olustu.")

    # ================================================================== #
    #  HTML RAPOR
    # ================================================================== #

    def generate_desktop_report(self, url, crawl_data, ww_items, sql_items,
                                  nikto_items, gb_items, nmap_items, dirb_items, wfuzz_items):
        domain = urlparse(url).netloc.replace("www.", "") or "site"
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def html_rows_generic(items, fields, color_field, color_map, vuln_fields=None):
            """
            Her satira tıklanınca detay popup acilir (onclick ile).
            vuln_fields: bulgu metnini olusturmak icin hangi field'lar kullanilacak
            """
            out = ""
            for item in items:
                bg    = color_map.get(item.get(color_field, ""), "#ffffff")
                # Turkce aciklamayi bul
                vtext = " ".join(str(item.get(f, "")) for f in (vuln_fields or fields))
                title, aciklama, risk, nasil, cozum = lookup_vuln(vtext)
                rc    = risk_color(risk)
                # Detay HTML - onclick ile goster
                detail_html = (
                    "<div style='display:none;margin-top:10px;padding:14px;"
                    "background:" + rc + ";border-radius:8px;font-size:.85rem'>"
                    "<strong style='font-size:1rem;color:#1e3a8a'>" + title + "</strong><br>"
                    "<span style='background:" + rc + ";padding:2px 8px;border-radius:10px;"
                    "font-weight:bold'>Risk: " + risk + "</span><br><br>"
                    "<strong>Nedir?</strong><br>" + aciklama + "<br><br>"
                    "<strong>Nasil Kullanilir?</strong><br>" + nasil + "<br><br>"
                    "<strong>Cozum:</strong><br>" + cozum +
                    "</div>"
                )
                tds = ""
                for f in fields:
                    tds += "<td>" + str(item.get(f, "")) + "</td>"
                out += (
                    "<tr style='background:" + bg + ";cursor:pointer' "
                    "onclick=\"var d=this.nextSibling;d.style.display=d.style.display=='table-row'?'none':'table-row'\">"
                    + tds + "</tr>"
                    "<tr style='display:none'><td colspan='" + str(len(fields)) + "'>"
                    + detail_html + "</td></tr>"
                )
            return out

        dir_color  = {"200": "#f0fdf4", "301": "#eff6ff", "302": "#eff6ff",
                      "403": "#fef3c7", "401": "#fef3c7", "500": "#fee2e2"}
        nmap_color = {"open": "#f0fdf4", "filtered": "#fef3c7", "closed": "#f9fafb", "VULN": "#fee2e2"}
        nikto_c    = {"HIGH": "#fee2e2", "MED": "#fef3c7", "LOW": "#eff6ff", "INFO": "#f9fafb"}
        sql_c      = {"ACIL": "#fee2e2", "VERI": "#fef3c7", "BILGI": "#eff6ff", "TEMIZ": "#f0fdf4"}

        nmap_rows  = html_rows_generic(nmap_items,  ["port","state","service","version","detail"], "state", nmap_color)
        nikto_rows = html_rows_generic(nikto_items, ["severity","msg"], "severity", nikto_c)
        sql_rows   = html_rows_generic(sql_items,   ["type","msg"], "type", sql_c)
        gb_rows    = html_rows_generic(gb_items,    ["status","path","size"], "status", dir_color)
        dirb_rows  = html_rows_generic(dirb_items,  ["status","url","size"], "status", dir_color)
        wfuzz_rows = html_rows_generic(wfuzz_items, ["status","words","lines","chars","url"], "status", dir_color)

        ww_rows = ""
        for item in ww_items:
            bg    = "#f0fdf4" if "OK" in item["category"] else "#ffffff"
            vtext = item["key"] + " " + item["description"]
            title, aciklama, risk, nasil, cozum = lookup_vuln(vtext)
            rc    = risk_color(risk)
            detail_html = (
                "<div style='display:none;margin-top:10px;padding:14px;"
                "background:" + rc + ";border-radius:8px;font-size:.85rem'>"
                "<strong style='color:#1e3a8a'>" + title + "</strong><br>"
                "<strong>Risk:</strong> " + risk + "<br><br>"
                "<strong>Nedir?</strong><br>" + aciklama + "<br><br>"
                "<strong>Cozum:</strong><br>" + cozum + "</div>"
            )
            ww_rows += (
                "<tr style='background:" + bg + ";cursor:pointer' "
                "onclick=\"var d=this.nextSibling;d.style.display=d.style.display=='table-row'?'none':'table-row'\">"
                "<td>" + item["emoji"] + "</td>"
                "<td><strong>" + item["key"] + "</strong></td>"
                "<td>" + item["category"] + "</td>"
                "<td>" + item["description"] + "</td>"
                "<td>" + item["value"] + "</td></tr>"
                "<tr style='display:none'><td colspan='5'>" + detail_html + "</td></tr>"
            )

        form_rows = ""
        for frm in crawl_data["forms"]:
            badge_bg  = "#fee2e2" if frm["method"] == "post" else "#dbeafe"
            badge_col = "#b91c1c" if frm["method"] == "post" else "#1d4ed8"
            form_rows += (
                "<tr><td>" + frm["url"] + "</td>"
                "<td><span style='background:" + badge_bg + ";color:" + badge_col + ";"
                "padding:2px 8px;border-radius:10px;font-size:.8rem'>" + frm["method"].upper() + "</span></td>"
                "<td>" + ", ".join(frm["params"]) + "</td></tr>"
            )
        param_rows = "".join(
            "<tr><td><a href='" + p + "' target='_blank'>" + p + "</a></td></tr>"
            for p in crawl_data["params"]
        )

        def section(title, count, th_list, rows, note="Satıra tıklayın → Türkçe detay"):
            ths = "".join("<th>" + h + "</th>" for h in th_list)
            return (
                "<div class='sec'><h3>" + title + " (" + str(count) + ")"
                "<span style='font-size:.8rem;font-weight:normal;color:#6b7280;margin-left:12px'>"
                + note + "</span></h3>"
                "<table><tr>" + ths + "</tr>" + rows + "</table></div>"
            )

        css = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#f0f2f5;padding:30px}
.hdr{background:linear-gradient(135deg,#1e40af,#2563eb);color:#fff;
     padding:28px;border-radius:14px;text-align:center;margin-bottom:22px}
.hdr h1{font-size:1.7rem;margin-bottom:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
      gap:14px;margin-bottom:20px}
.card{background:#fff;padding:18px;border-radius:10px;box-shadow:0 3px 10px rgba(0,0,0,.08)}
.cr{border-left:5px solid #ef4444}
.wa{border-left:5px solid #f59e0b}
.in{border-left:5px solid #3b82f6}
.su{border-left:5px solid #10b981}
.pu{border-left:5px solid #8b5cf6}
.sec{background:#fff;padding:20px;border-radius:10px;
     box-shadow:0 3px 10px rgba(0,0,0,.08);margin-bottom:20px}
.sec h3{color:#1e3a8a;margin-bottom:10px}
a{color:#2563eb;font-weight:bold;text-decoration:none}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{background:#1e40af;color:#fff;padding:8px;text-align:left}
td{padding:6px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top}
tr[onclick]:hover td{filter:brightness(.96)}
"""

        html = (
            "<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>"
            "<title>" + domain + " Report</title>"
            "<style>" + css + "</style></head><body>"
            "<div class='hdr'>"
            "<h1>" + domain + " Penetration Test Report</h1>"
            "<p>" + now + " &mdash; " + url + "</p>"
            "<p style='margin-top:8px;font-size:.9rem;opacity:.85'>"
            "Tablolardaki satırlara tıklayarak Türkçe açıklama, risk seviyesi ve çözüm önerisini görebilirsiniz.</p>"
            "</div>"
            "<div class='grid'>"
            "<div class='card pu'><h3>Nmap</h3><p style='color:#6b7280'>" + str(len(nmap_items)) + " port/servis</p><p><a href='nmap_report.txt'>Ham</a></p></div>"
            "<div class='card cr'><h3>Nikto</h3><p style='color:#6b7280'>" + str(len(nikto_items)) + " bulgu</p><p><a href='nikto_report.txt'>Ham</a></p></div>"
            "<div class='card cr'><h3>SQLMap</h3><p style='color:#6b7280'>" + str(len(sql_items)) + " sonuc</p><p><a href='sqlmap/'>Klasor</a></p></div>"
            "<div class='card wa'><h3>Gobuster</h3><p style='color:#6b7280'>" + str(len(gb_items)) + " dizin</p><p><a href='gobuster.txt'>Ham</a></p></div>"
            "<div class='card wa'><h3>Dirb</h3><p style='color:#6b7280'>" + str(len(dirb_items)) + " dizin</p><p><a href='dirb_report.txt'>Ham</a></p></div>"
            "<div class='card wa'><h3>Wfuzz</h3><p style='color:#6b7280'>" + str(len(wfuzz_items)) + " sonuc</p><p><a href='wfuzz_report.csv'>Ham</a></p></div>"
            "<div class='card in'><h3>WhatWeb</h3><p style='color:#6b7280'>" + str(len(ww_items)) + " bilesen</p><p><a href='whatweb_report.txt'>Ham</a></p></div>"
            "<div class='card su'><h3>Formlar</h3><p style='color:#6b7280'>" + str(len(crawl_data["forms"])) + " form / " + str(len(crawl_data["params"])) + " URL</p><p><a href='crawl_report.txt'>Rapor</a></p></div>"
            "</div>"
            + section("Nmap Port Taramasi", len(nmap_items), ["Port","Durum","Servis","Versiyon","Detay"], nmap_rows)
            + section("Nikto Bulgulari",    len(nikto_items), ["Seviye","Bulgu"], nikto_rows)
            + section("SQLMap Sonuclari",   len(sql_items),   ["Tur","Bilgi"], sql_rows)
            + section("WhatWeb Analizi",    len(ww_items),    ["","Bilesen","Kategori","Aciklama","Deger"], ww_rows)
            + section("Gobuster Dizinler",  len(gb_items),    ["Durum","Yol","Boyut"], gb_rows)
            + section("Dirb Dizinler",      len(dirb_items),  ["Durum","URL","Boyut"], dirb_rows)
            + section("Wfuzz Sonuclari",    len(wfuzz_items), ["Durum","Kelime","Satir","Karakter","URL"], wfuzz_rows)
            + "<div class='sec'><h3>Formlar (" + str(len(crawl_data["forms"])) + ")</h3>"
            + "<table><tr><th>URL</th><th>Metod</th><th>Parametreler</th></tr>" + form_rows + "</table></div>"
            + "<div class='sec'><h3>Parametreli URL (" + str(len(crawl_data["params"])) + ")</h3>"
            + "<table><tr><th>URL</th></tr>" + param_rows + "</table></div>"
            + "</body></html>"
        )

        report_path = os.path.join(self.report_folder, "DESKTOP_REPORT.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        self.log("HTML rapor olusturuldu: DESKTOP_REPORT.html")

    # ================================================================== #
    #  KLASÖR / RAPOR AÇMA
    # ================================================================== #

    def open_desktop(self):
        target = (self.report_folder if self.report_folder and os.path.exists(self.report_folder)
                  else self.desktop_path)
        if platform.system() == "Windows":
            os.startfile(target)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])

    def open_report_html(self):
        if self.report_folder:
            p = os.path.join(self.report_folder, "DESKTOP_REPORT.html")
            if os.path.exists(p):
                webbrowser.open("file://" + os.path.abspath(p))
            else:
                messagebox.showinfo("Bilgi", "Rapor henuz olusturulmadi.")
        else:
            messagebox.showinfo("Bilgi", "Once bir tarama baslatin.")


# ================================================================== #
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    root = tk.Tk()
    app  = DesktopHunter(root)
    root.mainloop()
