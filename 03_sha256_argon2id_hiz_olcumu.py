import os
import sys
import time
import hashlib
from argon2 import PasswordHasher

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
os.system("")

R, BOLD = "\033[0m", "\033[1m"
RED, GREEN, YELLOW, CYAN, GRAY = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[90m"

parola = b"ornek-parola-123"
SHA_TEKRAR = 100_000      # SHA-256 çok hızlı, çok kez tekrarlıyoruz
ARGON_TEKRAR = 10         # Argon2id yavaş, az tekrar yeterli

print("\n" + CYAN + "═" * 66 + R)
print(CYAN + BOLD + "  LABORATUVAR VI  ·  SHA-256 ve Argon2id Hız Ölçümü" + R)
print(CYAN + "═" * 66 + R)

# ---------- SHA-256 ----------
print(f"\n{YELLOW}{BOLD}[1]{R} SHA-256 ölçülüyor ({SHA_TEKRAR:,} tekrar)...")
t0 = time.perf_counter()
for _ in range(SHA_TEKRAR):
    hashlib.sha256(parola).digest()
sha_toplam = time.perf_counter() - t0
sha_ort = sha_toplam / SHA_TEKRAR

# ---------- Argon2id ----------
ph = PasswordHasher()     # varsayılan tür: Argon2id
print(f"{YELLOW}{BOLD}[2]{R} Argon2id ölçülüyor ({ARGON_TEKRAR} tekrar)...")
t0 = time.perf_counter()
for _ in range(ARGON_TEKRAR):
    ph.hash(parola.decode())
arg_toplam = time.perf_counter() - t0
arg_ort = arg_toplam / ARGON_TEKRAR

# ---------- Sonuç ----------
oran = arg_ort / sha_ort
sha_sn = 1 / sha_ort
arg_sn = 1 / arg_ort

print("\n" + CYAN + "─" * 66 + R)
print(f"  {BOLD}{'Algoritma':<14}{'Ort. süre':<20}{'Saniyede deneme':<20}{R}")
print("  " + "─" * 54)
print(f"  {'SHA-256':<14}{sha_ort * 1e6:>10.2f} µs      {sha_sn:>14,.0f}")
print(f"  {'Argon2id':<14}{arg_ort * 1e3:>10.2f} ms      {arg_sn:>14,.1f}")
print(CYAN + "─" * 66 + R)

print(f"\n  {BOLD}Argon2id, SHA-256'dan yaklaşık {RED}{oran:,.0f} kat{R}{BOLD} daha yavaş.{R}")
print(f"\n  {GRAY}Yorum: Parola kırmaya çalışan saldırgan saniyede çok deneme yapmak ister.")
print(f"  SHA-256 hızlı olduğu için parola saklamada kötü bir seçimdir.")
print(f"  Argon2id kasıtlı olarak yavaş ve bellek yoğundur; her denemeyi pahalı")
print(f"  yaparak kaba kuvvet saldırısını zorlaştırır.{R}\n")