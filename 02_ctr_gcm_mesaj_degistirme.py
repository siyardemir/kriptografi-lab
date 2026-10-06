import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Türkçe karakterler ve renkler için (Windows dahil)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
os.system("")

# ---------- Görünüm yardımcıları ----------
R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GRAY = "\033[90m"
W = 72


def baslik(metin):
    print("\n" + CYAN + "═" * W + R)
    print(CYAN + BOLD + "  " + metin + R)
    print(CYAN + "═" * W + R)


def adim(no, metin):
    print(f"\n{YELLOW}{BOLD}[{no}]{R} {BOLD}{metin}{R}")


def bilgi(etiket, deger):
    print(f"    {GRAY}{etiket:<22}{R}{deger}")


def basari(metin):
    print(f"    {GREEN}{BOLD}✔ {metin}{R}")


def hata(metin):
    print(f"    {RED}{BOLD}✘ {metin}{R}")


# ---------- Deney verisi ----------
anahtar = os.urandom(16)              # 128 bit anahtar
eski = b"Tutar: 100 TL"
yeni = b"Tutar: 900 TL"

baslik("LABORATUVAR VI  ·  CTR ve AES-GCM: Mesaj Değiştirme Deneyi")
bilgi("Anahtar (hex)", anahtar.hex())
bilgi("Orijinal mesaj", eski.decode())
bilgi("Saldırganın hedefi", yeni.decode())
print(f"    {GRAY}Saldırgan anahtarı BİLMİYOR; sadece şifreli metni görüyor.{R}")

# =====================================================================
# BÖLÜM 1: AES-CTR
# =====================================================================
baslik("BÖLÜM 1  ·  AES-CTR (kimlik doğrulaması YOK)")

nonce = os.urandom(16)
e = Cipher(algorithms.AES(anahtar), modes.CTR(nonce)).encryptor()
sifreli = e.update(eski) + e.finalize()

adim(1, "Gönderici mesajı şifreler")
bilgi("Nonce (hex)", nonce.hex())
bilgi("Şifreli (hex)", sifreli.hex())

adim(2, "Saldırgan şifreli metni XOR ile değiştirir")
print(f"    {GRAY}yeni_sifreli = sifreli ⊕ eski_mesaj ⊕ yeni_mesaj{R}\n")
oynanmis = bytes(c ^ a ^ b for c, a, b in zip(sifreli, eski, yeni))

print(f"    {BOLD}{'Sıra':<6}{'Eski':<8}{'Yeni':<8}{'Şifreli':<10}{'Oynanmış':<10}{R}")
print("    " + "─" * 40)
for i, (a, b, c, o) in enumerate(zip(eski, yeni, sifreli, oynanmis)):
    degisti = a != b
    renk = RED + BOLD if degisti else GRAY
    isaret = " ◄ değişti" if degisti else ""
    print(f"    {renk}{i:<6}{chr(a):<8}{chr(b):<8}{c:02x}{'':<8}{o:02x}{isaret}{R}")

adim(3, "Alıcı (doğru anahtarla) çözer")
d = Cipher(algorithms.AES(anahtar), modes.CTR(nonce)).decryptor()
sonuc_ctr = d.update(oynanmis) + d.finalize()
bilgi("Çözülen mesaj", f"{RED}{BOLD}{sonuc_ctr.decode()}{R}")
if sonuc_ctr == yeni:
    hata("SALDIRI BAŞARILI: Alıcı değişikliği fark etmedi, 900 TL olarak okudu!")
    print(f"    {GRAY}Neden? CTR'da şifreli = mesaj ⊕ anahtar_akışı. Bir bit çevirirsen{R}")
    print(f"    {GRAY}çözümde aynı bit çevrilir. Bütünlük kontrolü yok.{R}")

# =====================================================================
# BÖLÜM 2: AES-GCM
# =====================================================================
baslik("BÖLÜM 2  ·  AES-GCM (kimlik doğrulaması VAR)")

aes = AESGCM(anahtar)
n = os.urandom(12)
paket = aes.encrypt(n, eski, None)    # şifreli metin + 16 bayt etiket (tag)
sifreli_gcm = paket[:-16]
etiket = paket[-16:]

adim(1, "Gönderici mesajı şifreler")
bilgi("Nonce (hex)", n.hex())
bilgi("Şifreli (hex)", sifreli_gcm.hex())
bilgi("Etiket / tag (hex)", etiket.hex())

adim(2, "Değiştirilmemiş paket çözülür (kontrol)")
bilgi("Çözülen mesaj", f"{GREEN}{BOLD}{aes.decrypt(n, paket, None).decode()}{R}")
basari("Bozulmamış paket sorunsuz çözüldü")


def saldir(ad, bozuk_paket):
    adim(ad[0], ad[1])
    try:
        sonuc = aes.decrypt(n, bozuk_paket, None)
        hata(f"Saldırı başarılı?! Çözülen: {sonuc.decode()}")
    except InvalidTag:
        basari("InvalidTag: DEĞİŞİKLİK TESPİT EDİLDİ, mesaj reddedildi")


# Saldırı A: tek bayt boz
bozuk_a = bytearray(paket)
bozuk_a[10] ^= 1
saldir((3, "Saldırı A: şifreli metnin tek baytı bozulur"), bytes(bozuk_a))

# Saldırı B: CTR'daki XOR saldırısının aynısı
oyn_gcm = bytes(c ^ a ^ b for c, a, b in zip(sifreli_gcm, eski, yeni))
saldir((4, "Saldırı B: CTR'daki XOR saldırısı GCM'e uygulanır"), oyn_gcm + etiket)

# Saldırı C: etiketi boz
bozuk_c = bytearray(paket)
bozuk_c[-1] ^= 1
saldir((5, "Saldırı C: etiket (tag) bozulur"), bytes(bozuk_c))

# =====================================================================
# ÖZET
# =====================================================================
baslik("SONUÇ")
print(f"    {BOLD}{'Özellik':<28}{'AES-CTR':<14}{'AES-GCM':<14}{R}")
print("    " + "─" * 54)
satirlar = [
    ("Gizlilik", "var", "var"),
    ("Bütünlük / kimlik doğrulama", "YOK", "var"),
    ("Mesaj anahtarsız değişir mi?", "EVET", "HAYIR"),
    ("Değişiklik fark edilir mi?", "HAYIR", "EVET"),
]
for ad, a, b in satirlar:
    ra = RED if a in ("YOK", "EVET") and "değişir" in ad else (RED if a in ("YOK", "HAYIR") else GREEN)
    rb = GREEN if b in ("var", "HAYIR", "EVET") else RED
    if "değişir mi" in ad:
        ra, rb = RED, GREEN
    print(f"    {ad:<28}{ra}{a:<14}{R}{rb}{b:<14}{R}")

print(f"\n    {BOLD}Çıkarım:{R} Şifreleme tek başına yetmez; bütünlük de gerekir.")
print(f"    {GRAY}Bu yüzden pratikte AES-GCM gibi AEAD modları kullanılmalı.{R}\n")