#!/usr/bin/env python3
import os, json, hashlib, zipfile, tempfile, requests, re, shutil, subprocess
from flask import Flask, jsonify, send_file
from PIL import Image, ImageDraw

app = Flask(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://iiocxlvcuoqafzlisqwd.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
PASS_TYPE    = "pass.com.mysargal.app"
TEAM_ID      = "6779DNV7Y5"
GREEN        = (0, 190, 92)

def get_headers():
    return {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}

def fmt_cfa(n):
    return f"{int(n):,} CFA".replace(",", " ")

def make_icon(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, size-1, size-1], radius=size//5, fill=GREEN)
    cx, cy = size//2, size//2
    bw, bh = int(size*.50), int(size*.30)
    bx, by = cx-bw//2, cy-bh//2+int(size*.06)
    d.rectangle([bx, by, bx+bw, by+bh], fill=(255,255,255))
    lh = int(size*.11)
    d.rectangle([bx-2, by-lh, bx+bw+2, by], fill=(255,255,255))
    rw = max(int(size*.07), 2)
    d.rectangle([cx-rw//2, by-lh-2, cx+rw//2, by+bh], fill=GREEN)
    br = int(size*.08)
    d.ellipse([cx-br*2-1, by-lh-br, cx-1, by-lh+br], fill=(255,255,255))
    d.ellipse([cx+1, by-lh-br, cx+br*2+1, by-lh+br], fill=(255,255,255))
    return img

def save_images(folder):
    for size, suffix in [(29,""),(58,"@2x"),(87,"@3x")]:
        make_icon(size).save(f"{folder}/icon{suffix}.png")
    make_icon(60).save(f"{folder}/logo.png")
    make_icon(120).save(f"{folder}/logo@2x.png")
    Image.new("RGB", (375, 90), GREEN).save(f"{folder}/strip.png")
    Image.new("RGB", (750, 180), GREEN).save(f"{folder}/strip@2x.png")

def sign_manifest(folder):
    openssl = shutil.which("openssl") or "/usr/bin/openssl"
    base = os.path.dirname(os.path.abspath(__file__))
    p12_path  = os.path.join(base, "mysargal-pass.p12")
    wwdr_path = os.path.join(base, "AppleWWDRCAG4.pem")
    p12_pass  = "mysargal123"

    # Extraire cert du p12
    cert_tmp = f"{folder}/cert_tmp.pem"
    key_tmp  = f"{folder}/key_tmp.pem"

    r1 = subprocess.run([
        openssl, "pkcs12", "-legacy",
        "-in", p12_path, "-passin", f"pass:{p12_pass}",
        "-nokeys", "-clcerts", "-out", cert_tmp
    ], capture_output=True)

    # Si -legacy echoue, essayer sans
    if r1.returncode != 0:
        r1 = subprocess.run([
            openssl, "pkcs12",
            "-in", p12_path, "-passin", f"pass:{p12_pass}",
            "-nokeys", "-clcerts", "-out", cert_tmp
        ], capture_output=True)

    # Extraire key
    r2 = subprocess.run([
        openssl, "pkcs12", "-legacy",
        "-in", p12_path, "-passin", f"pass:{p12_pass}",
        "-nocerts", "-nodes", "-out", key_tmp
    ], capture_output=True)

    if r2.returncode != 0:
        r2 = subprocess.run([
            openssl, "pkcs12",
            "-in", p12_path, "-passin", f"pass:{p12_pass}",
            "-nocerts", "-nodes", "-out", key_tmp
        ], capture_output=True)

    # Utiliser pass-cert-only.pem si p12 ne contient pas le bon cert
    cert_path = os.path.join(base, "pass-cert-only.pem")
    key_path  = os.path.join(base, "mysargal-pass.key")

    # Signer
    result = subprocess.run([
        openssl, "smime", "-sign", "-binary",
        "-signer", cert_path,
        "-inkey", key_path,
        "-certfile", wwdr_path,
        "-in", f"{folder}/manifest.json",
        "-out", f"{folder}/signature",
        "-outform", "DER"
    ], capture_output=True)

    if result.returncode != 0:
        raise Exception(f"Sign error: {result.stderr.decode()[:300]}")
    return True

def build_pass(folder, pass_json, out_path):
    with open(f"{folder}/pass.json", "w") as f:
        json.dump(pass_json, f, ensure_ascii=False)
    manifest = {}
    for fn in sorted(os.listdir(folder)):
        if fn in ("manifest.json", "signature"): continue
        fp = f"{folder}/{fn}"
        if os.path.isfile(fp):
            with open(fp, "rb") as f:
                manifest[fn] = hashlib.sha1(f.read()).hexdigest()
    with open(f"{folder}/manifest.json", "w") as f:
        json.dump(manifest, f)
    sign_manifest(folder)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fn in os.listdir(folder):
            if os.path.isfile(f"{folder}/{fn}"):
                zf.write(f"{folder}/{fn}", fn)

def get_merchant(merchant_id):
    r = requests.get(f"{SUPABASE_URL}/rest/v1/merchants?id=eq.{merchant_id}&select=id,name,threshold", headers=get_headers(), timeout=10)
    data = r.json()
    return data[0] if data else {"name": "MySargal", "threshold": 100}

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/passes/<code>.pkpass")
def generate_pass(code):
    try:
        with tempfile.TemporaryDirectory() as folder:
            save_images(folder)
            if code.startswith("LC-"):
                r = requests.get(f"{SUPABASE_URL}/rest/v1/loyalty_cards?code=eq.{code}&select=*", headers=get_headers(), timeout=10)
                cards = r.json()
                if not cards: return jsonify({"error": "Carte non trouvee"}), 404
                card = cards[0]
                merchant = get_merchant(card.get("merchant_id", ""))
                pts = card.get("pts", 0)
                thr = merchant.get("threshold", 100)
                mname = merchant.get("name", "MySargal")
                pass_json = {
                    "formatVersion":1,"passTypeIdentifier":PASS_TYPE,"serialNumber":code,
                    "teamIdentifier":TEAM_ID,"organizationName":"MySargal",
                    "description":f"Carte Fidelite — {mname}","logoText":"",
                    "backgroundColor":"rgb(240,252,235)","foregroundColor":"rgb(10,10,10)","labelColor":"rgb(0,150,70)",
                    "storeCard":{
                        "headerFields":[{"key":"b","label":"BOUTIQUE","value":mname}],
                        "primaryFields":[{"key":"p","label":"POINTS","value":str(pts)}],
                        "secondaryFields":[{"key":"c","label":"CLIENT","value":card.get("client_name","")},{"key":"t","label":"PALIER","value":f"{thr} pts"}],
                        "auxiliaryFields":[{"key":"cd","label":"CODE","value":code}],
                        "backFields":[{"key":"i","label":"Utiliser","value":"Presentez le QR code en caisse."}]
                    },
                    "barcodes":[{"message":f"https://mysargal.com/c/?code={code}","format":"PKBarcodeFormatQR","messageEncoding":"iso-8859-1","altText":code}]
                }
            elif code.startswith("GC-"):
                r = requests.get(f"{SUPABASE_URL}/rest/v1/gift_cards?code=eq.{code}&select=*", headers=get_headers(), timeout=10)
                cards = r.json()
                if not cards: return jsonify({"error": "Carte non trouvee"}), 404
                gc = cards[0]
                merchant = get_merchant(gc.get("merchant_id", ""))
                mname = merchant.get("name", "MySargal")
                bal = gc.get("balance", 0)
                init = gc.get("initial_amount", 0)
                exp = gc.get("expires_at", "N/A")
                if exp and exp != "N/A":
                    try:
                        from datetime import datetime
                        exp = datetime.fromisoformat(exp.replace("Z","+00:00")).strftime("%b %Y")
                    except: pass
                pass_json = {
                    "formatVersion":1,"passTypeIdentifier":PASS_TYPE,"serialNumber":code,
                    "teamIdentifier":TEAM_ID,"organizationName":"MySargal",
                    "description":f"Carte Cadeau — {mname}","logoText":"",
                    "backgroundColor":"rgb(240,252,235)","foregroundColor":"rgb(10,10,10)","labelColor":"rgb(0,150,70)",
                    "storeCard":{
                        "headerFields":[{"key":"b","label":"BOUTIQUE","value":mname}],
                        "primaryFields":[{"key":"s","label":"SOLDE","value":fmt_cfa(bal)}],
                        "secondaryFields":[{"key":"r","label":"BENEFICIAIRE","value":gc.get("recipient_name","")},{"key":"e","label":"EXPIRE","value":exp}],
                        "auxiliaryFields":[{"key":"cd","label":"CODE","value":code},{"key":"in","label":"INITIAL","value":fmt_cfa(init)}],
                        "backFields":[{"key":"i","label":"Utiliser","value":"Presentez le QR code en caisse."}]
                    },
                    "barcodes":[{"message":f"https://mysargal.com/c/?code={code}","format":"PKBarcodeFormatQR","messageEncoding":"iso-8859-1","altText":code}]
                }
            else:
                return jsonify({"error": "Code invalide"}), 400

            out_path = f"/tmp/{code}.pkpass"
            build_pass(folder, pass_json, out_path)
            return send_file(out_path, mimetype="application/vnd.apple.pkpass", as_attachment=False, download_name=f"{code}.pkpass")
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()[-500:]}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
