import os
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Görüntüyü aç, RGB olarak al
klasor = os.path.dirname(os.path.abspath(__file__))
img = Image.open(os.path.join(klasor, "images.jpg")).convert("RGB")
ham = img.tobytes()          # piksel verisi (ham bayt)
boyut = img.size

# AES blok boyutu 16 bayt; veriyi 16'nın katına tamamla
dolgu = (-len(ham)) % 16
ham_dolgulu = ham + b"\x00" * dolgu

anahtar = os.urandom(16)     # 128 bit anahtar

# --- ECB ---
ecb = Cipher(algorithms.AES(anahtar), modes.ECB()).encryptor()
ecb_sifreli = ecb.update(ham_dolgulu) + ecb.finalize()

# --- CTR ---
nonce = os.urandom(16)
ctr = Cipher(algorithms.AES(anahtar), modes.CTR(nonce)).encryptor()
ctr_sifreli = ctr.update(ham_dolgulu) + ctr.finalize()

# Şifreli baytlardan tekrar görüntü üret (dolguyu at)
n = len(ham)
img_ecb = Image.frombytes("RGB", boyut, ecb_sifreli[:n])
img_ctr = Image.frombytes("RGB", boyut, ctr_sifreli[:n])

# Yan yana birleştir: etiketli ve çerçeveli
w, h = boyut
serit, bosluk = 50, 15

try:
    yazi = ImageFont.truetype("arialbd.ttf", 30)
except OSError:
    yazi = ImageFont.load_default()

sonuc = Image.new("RGB", (w * 3 + bosluk * 4, h + serit + bosluk * 2), "white")
cizim = ImageDraw.Draw(sonuc)

parcalar = [(img, "ORİJİNAL"), (img_ecb, "AES-ECB"), (img_ctr, "AES-CTR")]
for i, (resim, etiket) in enumerate(parcalar):
    x = bosluk + i * (w + bosluk)
    y = bosluk + serit

    kutu = cizim.textbbox((0, 0), etiket, font=yazi)
    cizim.text((x + (w - (kutu[2] - kutu[0])) // 2, bosluk + 5),
               etiket, fill="black", font=yazi)

    sonuc.paste(resim, (x, y))
    cizim.rectangle([x - 3, y - 3, x + w + 2, y + h + 2], outline="black", width=3)

sonuc.save(os.path.join(klasor, "karsilastirma.png"))
sonuc.show()