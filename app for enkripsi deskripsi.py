"""
Aplikasi Enkripsi & Dekripsi RSA (input p dan q manual) - versi Streamlit
Memakai kode ASCII (0-127) untuk tiap karakter pesan, dengan ukuran blok yang bisa dipilih.
Jalankan lokal: streamlit run app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.

Cara kerja blok:
- Tiap karakter -> kode ASCII 3 digit (mis. 'A' = 065).
- k karakter digabung jadi satu blok angka (mis. "AB" -> 065066 -> m = 65066).
- Syarat: m < n untuk semua kemungkinan blok, yaitu "127" * k < n.
- Blok terakhir yang kurang dari k karakter diisi padding kode 0 (NUL),
  dan padding itu dibuang lagi saat dekripsi.
"""
from math import gcd, isqrt

import streamlit as st


# ---------------- Logika RSA ----------------
def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def mod_inverse(e, phi):
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError("e tidak punya invers modular terhadap phi(n)")
    return old_s % phi


def generate_keys(p, q, e=None):
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p dan q harus bilangan prima.")
    if p == q:
        raise ValueError("p dan q tidak boleh sama.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if n <= 127:
        raise ValueError(
            f"n = {n} terlalu kecil. Untuk kode ASCII (0-127) butuh n > 127, "
            "gunakan p dan q yang lebih besar."
        )
    if e is None:
        e = 3
        while e < phi and gcd(e, phi) != 1:
            e += 2
        if e >= phi:
            raise ValueError("Tidak ada e yang valid, coba p dan q lain.")
    elif not (1 < e < phi) or gcd(e, phi) != 1:
        raise ValueError(f"e harus 1 < e < {phi} dan koprima dengan phi(n).")
    d = mod_inverse(e, phi)
    return n, phi, e, d


def gcd_tries(e_input, phi):
    """Daftar (e, gcd(e, phi)) yang dicoba sampai ketemu e yang koprima."""
    if e_input:
        return [(e_input, gcd(e_input, phi))]
    tries, e = [], 3
    while True:
        g = gcd(e, phi)
        tries.append((e, g))
        if g == 1 or e >= phi:
            return tries
        e += 2


def euclid_steps(e, phi):
    """Tabel extended Euclid untuk mencari d. Baris: (langkah, q, r, s)."""
    rows = [("awal", "-", e, 1), ("awal", "-", phi, 0)]
    old_r, r = e, phi
    old_s, s = 1, 0
    step = 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        step += 1
        rows.append((step, q, r, s))
    return rows, old_r, old_s  # old_r = gcd, old_s = koefisien e


# ---------------- Logika blok ----------------
def max_block_size(n):
    """Ukuran blok terbesar (karakter/blok) agar semua blok pasti < n."""
    k = 1
    while int("127" * (k + 1)) < n:
        k += 1
    return k


def show_char(c):
    """Tampilan aman untuk satu karakter di tabel."""
    if c == 0:
        return "∅"  # padding
    if c == 32:
        return "␣"
    if c < 32 or c == 127:
        return f"[{c}]"
    return chr(c)


def encrypt_blocks(text, e, n, k):
    """Return (rows, jumlah_padding).
    rows: (no, karakter, kode ASCII gabungan, m, cipher)."""
    codes = []
    for ch in text:
        code = ord(ch)
        if code > 127:
            raise ValueError(f"Karakter '{ch}' bukan ASCII (0-127).")
        codes.append(code)

    pad = (-len(codes)) % k
    codes += [0] * pad

    rows = []
    for i in range(0, len(codes), k):
        chunk = codes[i:i + k]
        digits = "".join(f"{c:03d}" for c in chunk)
        m = int(digits)
        if m >= n:  # pengaman, seharusnya tidak terjadi karena k <= max_block_size
            raise ValueError("Blok melebihi n, perkecil ukuran blok.")
        rows.append((
            len(rows) + 1,
            "".join(show_char(c) for c in chunk),
            digits,
            m,
            pow(m, e, n),
        ))
    return rows, pad


def decrypt_blocks(cipher, d, n, k):
    """Return (rows, plaintext).
    rows: (no, cipher, m, kode ASCII gabungan, karakter)."""
    rows, all_codes = [], []
    for tok in cipher.split():
        c = int(tok)
        if not 0 <= c < n:
            raise ValueError("Ciphertext harus 0 <= c < n.")
        m = pow(c, d, n)
        digits = str(m).zfill(3 * k)
        if len(digits) > 3 * k:
            raise ValueError("Ukuran blok tidak cocok dengan ciphertext.")
        codes = [int(digits[i:i + 3]) for i in range(0, 3 * k, 3)]
        if any(x > 127 for x in codes):
            raise ValueError("Hasil bukan kode ASCII, kunci atau ukuran blok tidak cocok.")
        rows.append((
            len(rows) + 1,
            c,
            m,
            digits,
            "".join(show_char(x) for x in codes),
        ))
        all_codes.extend(codes)

    plaintext = "".join(chr(x) for x in all_codes).rstrip("\x00")  # buang padding
    return rows, plaintext


# ---------------- Tampilan ----------------
# Palet: Bow #7E2625, Warm Wood #3C1B0F, Candle #F1ECDB, Leaf #868859, Juniper #292F17
st.set_page_config(page_title="Enkripsi & Dekripsi RSA", layout="centered")

st.markdown(
    """
<style>
:root {
    --bow: #7E2625; --wood: #3C1B0F; --candle: #F1ECDB;
    --leaf: #868859; --juniper: #292F17;
}
.stApp { background: var(--candle); color: var(--wood); }
h1, h2, h3, label, p { color: var(--wood); }
.hero {
    background: linear-gradient(120deg, var(--juniper), var(--wood) 55%, var(--bow));
    padding: 28px 24px; border-radius: 20px; color: var(--candle); text-align: center;
    box-shadow: 0 10px 26px rgba(60, 27, 15, .35); margin-bottom: 18px;
    border-bottom: 6px solid var(--leaf);
}
.hero h1 { margin: 0; font-size: 2.2rem; color: var(--candle); }
.hero p  { margin: 6px 0 0; opacity: .95; font-size: 1.05rem; color: var(--candle); }
.section-title {
    display: inline-block; background: var(--juniper); color: var(--candle);
    padding: 6px 16px; border-radius: 999px; font-weight: 700;
    box-shadow: 0 3px 10px rgba(41, 47, 23, .25); margin: 14px 0 8px;
}
.key-card {
    border-radius: 16px; padding: 16px 18px; color: var(--candle);
    box-shadow: 0 6px 16px rgba(60, 27, 15, .22); margin-bottom: 10px;
}
.key-card .label { font-size: .85rem; opacity: .9; letter-spacing: .5px; }
.key-card .value { font-size: 1.15rem; font-weight: 700; word-break: break-all; }
.k-pub { background: var(--juniper); }
.k-prv { background: var(--bow); }
.step {
    background: #fffdf6; border-left: 8px solid var(--leaf); border-radius: 12px;
    padding: 12px 16px; margin: 10px 0; color: var(--wood);
    box-shadow: 0 4px 14px rgba(60, 27, 15, .10);
}
.step.s2 { border-left-color: var(--bow); }
.step.s3 { border-left-color: var(--juniper); }
.step.s4 { border-left-color: var(--wood); }
.step .st-title { font-weight: 700; color: var(--juniper); margin-bottom: 4px; }
.step .st-calc { font-family: monospace; font-size: 1.02rem; word-break: break-all; }
.step .st-note { font-size: .9rem; opacity: .85; margin-top: 4px; }
.step .ok { color: var(--juniper); font-weight: 700; }
.result-box {
    background: #fffdf6; border-left: 8px solid var(--bow); border-radius: 12px;
    padding: 14px 16px; color: var(--wood); word-break: break-all;
    box-shadow: 0 4px 14px rgba(60, 27, 15, .12); margin-top: 8px;
}
.result-box.dec { border-left-color: var(--leaf); }
.result-title { font-weight: 700; margin-bottom: 4px; color: var(--bow); }
.result-box.dec .result-title { color: var(--juniper); }
.tbl-wrap { max-height: 300px; overflow-y: auto; margin-top: 10px; border-radius: 12px;
    box-shadow: 0 4px 14px rgba(60, 27, 15, .12); }
table.steps { width: 100%; border-collapse: collapse; background: #fffdf6; }
table.steps th { background: var(--juniper); color: var(--candle); padding: 8px 10px;
    position: sticky; top: 0; text-align: center; }
table.steps td { padding: 6px 10px; text-align: center; color: var(--wood);
    border-bottom: 1px solid #e3dcc3; font-family: monospace; }
table.steps tr:nth-child(even) td { background: #f6f1e0; }
div.stButton > button {
    background: var(--bow); color: var(--candle); border: 2px solid var(--wood);
    border-radius: 12px; padding: 8px 26px; font-weight: 700;
    box-shadow: 0 5px 12px rgba(126, 38, 37, .35); transition: transform .15s;
}
div.stButton > button:hover {
    transform: translateY(-2px); background: var(--wood); color: var(--candle);
    border-color: var(--leaf);
}
button[data-baseweb="tab"] { font-weight: 700; font-size: 1.05rem; color: var(--wood); }
</style>
<div class="hero">
    <h1>Enkripsi & Dekripsi RSA</h1>
    <p>Masukkan sendiri nilai <b>p</b> dan <b>q</b> &middot; berbasis kode <b>ASCII</b> &middot; ukuran <b>blok</b> bisa dipilih</p>
</div>
""",
    unsafe_allow_html=True,
)


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def key_card(css, label, value):
    return (
        f'<div class="key-card {css}"><div class="label">{label}</div>'
        f'<div class="value">{value}</div></div>'
    )


def result_box(title, text, css=""):
    return (
        f'<div class="result-box {css}"><div class="result-title">{title}</div>'
        f"{esc(text)}</div>"
    )


def table(headers, rows):
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>" for r in rows
    )
    return (
        f'<div class="tbl-wrap"><table class="steps"><tr>{head}</tr>{body}</table></div>'
    )


def step_box(title, calc, note="", css=""):
    note_html = f'<div class="st-note">{note}</div>' if note else ""
    return (
        f'<div class="step {css}"><div class="st-title">{title}</div>'
        f'<div class="st-calc">{calc}</div>{note_html}</div>'
    )


# ---------------- 1. Input ----------------
st.markdown('<div class="section-title">Input Kunci</div>', unsafe_allow_html=True)
col1, col2, col3 = st.columns(3)
p = col1.number_input("p (prima)", min_value=2, value=1009, step=1)
q = col2.number_input("q (prima)", min_value=2, value=1013, step=1)
e_input = col3.number_input("e (0 = otomatis)", min_value=0, value=0, step=1)

keys = None
try:
    keys = generate_keys(int(p), int(q), int(e_input) or None)
except ValueError as ex:
    st.error(str(ex))

if keys:
    n, phi, e, d = keys
    p, q = int(p), int(q)

    # ---------------- Ukuran blok ----------------
    k_max = max_block_size(n)
    st.markdown('<div class="section-title">Ukuran Blok</div>', unsafe_allow_html=True)
    k = int(
        st.number_input(
            "Jumlah karakter per blok",
            min_value=1,
            max_value=k_max,
            value=min(2, k_max),
            step=1,
            help="Dipakai bersama di tab Enkripsi dan Dekripsi. "
                 "Ukuran blok saat dekripsi harus sama dengan saat enkripsi.",
        )
    )
    st.caption(
        f"Maksimal {k_max} karakter/blok untuk n = {n} "
        f"(syarat: {'127' * k_max} < n). Makin besar n, makin besar blok yang bisa dipakai."
    )

    # ---------------- Tab: Pembangkitan Kunci | Enkripsi | Dekripsi ----------------
    tab_key, tab_enc, tab_dec = st.tabs(["Pembangkitan Kunci", "Enkripsi", "Dekripsi"])

    # ---- Tab Pembangkitan Kunci: semua perhitungan kunci ----
    with tab_key:
        # Langkah 1: cek prima
        st.markdown(
            step_box(
                "Langkah 1 - Pastikan p dan q bilangan prima",
                f"p = {p} &rarr; prima &nbsp;|&nbsp; q = {q} &rarr; prima",
                f'Tidak habis dibagi bilangan 2 sampai {isqrt(p)} (untuk p) dan 2 sampai '
                f'{isqrt(q)} (untuk q), serta p &ne; q. <span class="ok">Valid</span>',
            ),
            unsafe_allow_html=True,
        )

        # Langkah 2: n
        st.markdown(
            step_box(
                "Langkah 2 - Hitung n",
                f"n = p &times; q = {p} &times; {q} = <b>{n}</b>",
                f'Syarat ASCII: n &gt; 127 &rarr; {n} &gt; 127 <span class="ok">Terpenuhi</span>',
                "s2",
            ),
            unsafe_allow_html=True,
        )

        # Langkah 3: phi
        st.markdown(
            step_box(
                "Langkah 3 - Hitung &phi;(n)",
                f"&phi;(n) = (p &minus; 1) &times; (q &minus; 1) = {p - 1} &times; {q - 1} = <b>{phi}</b>",
                css="s3",
            ),
            unsafe_allow_html=True,
        )

        # Langkah 4: pilih e
        tries = gcd_tries(int(e_input), phi)
        mode = "dimasukkan manual" if e_input else "dipilih otomatis (bilangan ganjil terkecil &gt; 1)"
        st.markdown(
            step_box(
                "Langkah 4 - Pilih e",
                f"Syarat: 1 &lt; e &lt; &phi;(n) dan FPB(e, &phi;(n)) = 1 &rarr; e = <b>{e}</b>",
                f"e {mode}.",
                "s4",
            ),
            unsafe_allow_html=True,
        )
        st.markdown(
            table(
                ["e yang dicoba", f"FPB(e, {phi})", "Koprima?"],
                [(te, g, "Ya" if g == 1 else "Tidak") for te, g in tries],
            ),
            unsafe_allow_html=True,
        )

        # Langkah 5: hitung d
        rows_eu, g, coef = euclid_steps(e, phi)
        st.markdown(
            step_box(
                "Langkah 5 - Hitung d (invers modular)",
                f"e &times; d &equiv; 1 (mod &phi;(n)) &rarr; {e} &times; d &equiv; 1 (mod {phi})",
                "Dihitung dengan algoritma Euclid yang diperluas. Kolom s adalah koefisien e; "
                f"FPB akhir = {g}, s terakhir sebelum sisa 0 = {coef}.",
            ),
            unsafe_allow_html=True,
        )
        st.markdown(
            table(["Langkah", "q (hasil bagi)", "r (sisa)", "s"], rows_eu),
            unsafe_allow_html=True,
        )
        st.markdown(
            step_box(
                "Hasil d",
                f"d = {coef} mod {phi} = <b>{d}</b>",
                f'Verifikasi: e &times; d mod &phi;(n) = {e} &times; {d} mod {phi} = '
                f'{(e * d) % phi} <span class="ok">Benar (harus 1)</span>',
                "s3",
            ),
            unsafe_allow_html=True,
        )

        # Langkah 6: ringkasan kunci
        st.markdown(
            step_box(
                "Langkah 6 - Kunci yang dihasilkan",
                f"Kunci Publik (e, n) = <b>({e}, {n})</b><br>"
                f"Kunci Privat (d, n) = <b>({d}, {n})</b>",
                "Kunci publik dipakai untuk enkripsi, kunci privat untuk dekripsi.",
                "s2",
            ),
            unsafe_allow_html=True,
        )

        # Langkah 7: batas ukuran blok
        st.markdown(
            step_box(
                "Langkah 7 - Batas ukuran blok",
                f"Blok terbesar k karakter = {'127' * k_max} (k = {k_max}) &lt; n = {n}",
                f'Dengan k = {k_max + 1} nilai blok bisa mencapai {"127" * (k_max + 1)} '
                f'&ge; n, sehingga tidak aman. Ukuran blok yang dipilih: <b>{k}</b> karakter.',
                "s4",
            ),
            unsafe_allow_html=True,
        )

    # ---- Tab Enkripsi: hanya kunci publik ----
    with tab_enc:
        st.markdown(
            key_card("k-pub", "Kunci Publik (e, n)", f"({e}, {n})"),
            unsafe_allow_html=True,
        )
        st.caption(f"Ukuran blok: {k} karakter/blok")
        plain = st.text_area("Plaintext (karakter ASCII)", height=120, key="plain",
                             placeholder="Ketik pesan rahasiamu di sini...")
        if st.button("Enkripsi"):
            if not plain:
                st.warning("Isi plaintext dulu.")
            else:
                try:
                    rows, pad = encrypt_blocks(plain, e, n, k)
                    cipher_out = " ".join(str(r[4]) for r in rows)
                    st.markdown(result_box("Ciphertext", cipher_out), unsafe_allow_html=True)
                    st.caption("Salin angka di atas ke tab Dekripsi "
                               "(ukuran blok harus sama).")
                    if pad:
                        st.caption(
                            f"Blok terakhir diisi {pad} karakter padding (kode 000, "
                            "tampil sebagai ∅) agar penuh."
                        )
                    st.markdown(
                        table(
                            ["Blok", "Karakter", "Kode ASCII gabungan", "m",
                             f"c = m<sup>{e}</sup> mod {n}"],
                            rows,
                        ),
                        unsafe_allow_html=True,
                    )
                except ValueError as ex:
                    st.error(str(ex))

    # ---- Tab Dekripsi: hanya kunci privat ----
    with tab_dec:
        st.markdown(
            key_card("k-prv", "Kunci Privat (d, n)", f"({d}, {n})"),
            unsafe_allow_html=True,
        )
        st.caption(f"Ukuran blok: {k} karakter/blok (samakan dengan saat enkripsi)")
        cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher",
                              placeholder="Tempel ciphertext di sini...")
        if st.button("Dekripsi"):
            if not cipher.strip():
                st.warning("Isi ciphertext dulu.")
            else:
                try:
                    rows, plain_out = decrypt_blocks(cipher, d, n, k)
                    st.markdown(result_box("Plaintext", plain_out, "dec"), unsafe_allow_html=True)
                    st.markdown(
                        table(
                            ["Blok", "Cipher c", f"m = c<sup>{d}</sup> mod {n}",
                             "Kode ASCII gabungan", "Karakter"],
                            rows,
                        ),
                        unsafe_allow_html=True,
                    )
                except (ValueError, OverflowError) as ex:
                    msg = str(ex)
                    if msg.startswith("invalid literal"):
                        msg = "Ciphertext harus berupa angka dipisah spasi."
                    st.error(
                        msg if msg and "kunci" in msg.lower() or "Ukuran blok" in msg
                        or "Ciphertext" in msg
                        else "Ciphertext tidak valid, atau kunci (p, q) / ukuran blok tidak cocok."
                    )
