"""
Aplikasi Enkripsi & Dekripsi RSA (input p dan q manual) - versi Streamlit
Memakai kode ASCII (0-127) untuk tiap karakter pesan.
Jalankan lokal: streamlit run app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.
"""
from math import gcd

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


def encrypt_steps(text, e, n):
    """Return list of (karakter, kode ASCII, cipher)."""
    rows = []
    for ch in text:
        code = ord(ch)
        if code > 127:
            raise ValueError(f"Karakter '{ch}' bukan ASCII (0-127).")
        rows.append((ch, code, pow(code, e, n)))
    return rows


def decrypt_steps(cipher, d, n):
    """Return list of (cipher, kode ASCII, karakter)."""
    rows = []
    for c in cipher.split():
        code = pow(int(c), d, n)
        if code > 127:
            raise ValueError("Hasil bukan kode ASCII, kunci tidak cocok.")
        rows.append((int(c), code, chr(code)))
    return rows


# ---------------- Tampilan ----------------
# Palet: Bow #7E2625, Warm Wood #3C1B0F, Candle #F1ECDB, Leaf #868859, Juniper #292F17
st.set_page_config(page_title="Enkripsi & Dekripsi RSA", page_icon="🔐", layout="centered")

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
.k-n   { background: var(--leaf); color: var(--juniper); }
.k-phi { background: var(--wood); }
.k-pub { background: var(--juniper); }
.k-prv { background: var(--bow); }
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
    <h1> Enkripsi & Dekripsi RSA</h1>
    <p>Masukkan sendiri nilai <b>p</b> dan <b>q</b> &middot; berbasis kode <b>ASCII</b></p>
</div>
""",
    unsafe_allow_html=True,
)


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def show_char(ch):
    names = {" ": "(spasi)", "\n": "\\n", "\t": "\\t", "\r": "\\r"}
    if ch in names:
        return names[ch]
    if ord(ch) < 32 or ord(ch) == 127:
        return f"(ctrl {ord(ch)})"
    return ch


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


st.markdown('<div class="section-title"> 1. Input Kunci</div>', unsafe_allow_html=True)
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

    c1, c2 = st.columns(2)
    c1.markdown(key_card("k-n", "n = p × q", n), unsafe_allow_html=True)
    c2.markdown(key_card("k-phi", "φ(n) = (p-1)(q-1)", phi), unsafe_allow_html=True)
    c3, c4 = st.columns(2)
    c3.markdown(key_card("k-pub", " Kunci Publik (e, n)", f"({e}, {n})"), unsafe_allow_html=True)
    c4.markdown(key_card("k-prv", " Kunci Privat (d, n)", f"({d}, {n})"), unsafe_allow_html=True)

    st.markdown('<div class="section-title"> 2. Pesan</div>', unsafe_allow_html=True)
    tab_enc, tab_dec = st.tabs([" Enkripsi", " Dekripsi"])

    with tab_enc:
        plain = st.text_area("Plaintext (karakter ASCII)", height=120, key="plain",
                             placeholder="Ketik pesan rahasiamu di sini...")
        if st.button(" Enkripsi"):
            if not plain:
                st.warning("Isi plaintext dulu.")
            else:
                try:
                    rows = encrypt_steps(plain, e, n)
                    cipher_out = " ".join(str(r[2]) for r in rows)
                    st.markdown(result_box(" Ciphertext", cipher_out), unsafe_allow_html=True)
                    st.caption("Salin angka di atas ke tab Dekripsi.")
                    st.markdown(
                        table(
                            ["Karakter", "ASCII (m)", f"Cipher (m^{e} mod {n})"],
                            [(show_char(ch), code, c) for ch, code, c in rows],
                        ),
                        unsafe_allow_html=True,
                    )
                except ValueError as ex:
                    st.error(str(ex))

    with tab_dec:
        cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher",
                              placeholder="Tempel ciphertext di sini...")
        if st.button("Dekripsi"):
            if not cipher.strip():
                st.warning("Isi ciphertext dulu.")
            else:
                try:
                    rows = decrypt_steps(cipher, d, n)
                    plain_out = "".join(r[2] for r in rows)
                    st.markdown(result_box("Plaintext", plain_out, "dec"), unsafe_allow_html=True)
                    st.markdown(
                        table(
                            ["Cipher (c)", f"ASCII (c^{d} mod {n})", "Karakter"],
                            [(c, code, show_char(ch)) for c, code, ch in rows],
                        ),
                        unsafe_allow_html=True,
                    )
                except (ValueError, OverflowError):
                    st.error("Ciphertext tidak valid atau kunci (p, q) tidak cocok.")
