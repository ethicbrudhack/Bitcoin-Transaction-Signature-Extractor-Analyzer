import requests
import hashlib
import struct
import time
import random
from ecdsa import util, SECP256k1
from collections import defaultdict
from base58 import b58encode_check
import os
import sys

RAW_TX_APIS = [
    "https://blockstream.info/api/tx/{}/hex",
    "https://blockchain.info/rawtx/{}?format=hex",
    "https://api.blockcypher.com/v1/btc/main/txs/{}?includeHex=true",
    "https://sochain.com/api/v2/tx/BTC/{}",
    "https://mempool.space/api/tx/{}/hex",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]

DELAY_BETWEEN_TX = 3  # Czas opóźnienia między kolejnymi TXID (w sekundach)
TXID_FILE = "txids.txt"
SIGNATURES_FILE = "signatures.txt"
LAST_TXID_FILE = "last_txid.txt"
api_failures = defaultdict(int)
MAX_RETRIES = 3

def get_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def zapisz_do_pliku(nazwa, linia):
    with open(nazwa, "a", encoding="utf-8") as f:
        f.write(linia + "\n")

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return b'\xfd' + struct.pack('<H', i)
    elif i <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', i)
    return b'\xff' + struct.pack('<Q', i)

def parse_pushdata(script_bytes):
    items = []
    i = 0
    while i < len(script_bytes):
        opcode = script_bytes[i]
        i += 1
        if opcode <= 75:
            items.append(script_bytes[i:i + opcode])
            i += opcode
        elif opcode == 76:
            length = script_bytes[i]
            i += 1
            items.append(script_bytes[i:i + length])
            i += length
        elif opcode == 77:
            length = int.from_bytes(script_bytes[i:i + 2], 'little')
            i += 2
            items.append(script_bytes[i:i + length])
            i += length
        else:
            items.append(bytes([opcode]))
    return items

def pubkey_to_address(pubkey_bytes):
    pubkey_sha = hashlib.sha256(pubkey_bytes).digest()
    pubkey_ripemd = hashlib.new("ripemd160", pubkey_sha).digest()
    prefix = b"\x00" + pubkey_ripemd
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return b58encode_check(prefix).decode()

def fetch_raw_tx(txid):
    for api in RAW_TX_APIS:
        if api_failures[api] >= MAX_RETRIES:
            continue
        try:
            url = api.format(txid)
            print("🌐 Próbuję pobrać TX z API:", url)
            r = requests.get(url, headers=get_headers(), timeout=20)
            if r.status_code == 200:
                raw = r.text.strip()
                if raw and all(c in "0123456789abcdefABCDEF" for c in raw):
                    return raw
        except Exception as e:
            print(f"❌ Błąd API: {api} -> {e}")
        api_failures[api] += 1
        time.sleep(random.uniform(1.0, 2.0))
    return None

def zdekoduj_transakcje(raw_tx_hex):
    data = bytes.fromhex(raw_tx_hex)
    offset = 0
    tx = {}
    tx["version"] = int.from_bytes(data[offset:offset + 4], "little")
    offset += 4

    def read_varint(data, offset):
        prefix = data[offset]
        offset += 1
        if prefix < 0xfd:
            return prefix, offset
        elif prefix == 0xfd:
            val = int.from_bytes(data[offset:offset + 2], 'little')
            offset += 2
            return val, offset
        elif prefix == 0xfe:
            val = int.from_bytes(data[offset:offset + 4], 'little')
            offset += 4
            return val, offset
        val = int.from_bytes(data[offset:offset + 8], 'little')
        offset += 8
        return val, offset

    vin_count, offset = read_varint(data, offset)
    vin = []
    for _ in range(vin_count):
        entry = {}
        entry["txid"] = data[offset:offset + 32][::-1].hex()
        offset += 32
        entry["vout"] = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        script_len, offset = read_varint(data, offset)
        entry["scriptSig"] = {"hex": data[offset:offset + script_len].hex()}
        offset += script_len
        entry["sequence"] = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        vin.append(entry)
    tx["vin"] = vin

    vout_count, offset = read_varint(data, offset)
    vout = []
    for _ in range(vout_count):
        entry = {}
        entry["value"] = int.from_bytes(data[offset:offset + 8], "little")
        offset += 8
        script_len, offset = read_varint(data, offset)
        entry["scriptPubKey"] = {"hex": data[offset:offset + script_len].hex()}
        offset += script_len
        vout.append(entry)
    tx["vout"] = vout
    tx["locktime"] = int.from_bytes(data[offset:offset + 4], "little")
    return tx

def process_transaction(txid):
    print("🔍 Analizuję TXID:", txid)
    raw_tx = fetch_raw_tx(txid)
    if not raw_tx:
        return
    try:
        tx = zdekoduj_transakcje(raw_tx)
    except:
        return

    for idx, vin in enumerate(tx["vin"]):
        script = vin.get("scriptSig", {}).get("hex", "")
        if not script:
            continue
        try:
            script_bytes = bytes.fromhex(script)
            parts = parse_pushdata(script_bytes)

            for i in range(len(parts) - 1):
                sig_candidate = parts[i]
                pub_candidate = parts[i + 1]

                # Sprawdź, czy to może być DER + pubkey (kompresowany lub nie)
                if len(sig_candidate) > 8 and sig_candidate[-1] == 0x01 and pub_candidate[0] in (0x02, 0x03, 0x04):
                    try:
                        r, s = util.sigdecode_der(sig_candidate[:-1], SECP256k1.order)
                        pubkey = pub_candidate
                        pubkey_hash = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
                        script_pub = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
                        version = struct.pack("<I", tx["version"])
                        locktime = struct.pack("<I", tx["locktime"])
                        input_count = encode_varint(len(tx["vin"]))
                        output_count = encode_varint(len(tx["vout"]))
                        inputs = b""
                        for j, v in enumerate(tx["vin"]):
                            inputs += bytes.fromhex(v["txid"])[::-1]
                            inputs += struct.pack("<I", v["vout"])
                            if j == idx:
                                inputs += encode_varint(len(script_pub)) + script_pub
                            else:
                                inputs += encode_varint(0)
                            inputs += struct.pack("<I", v["sequence"])
                        outputs = b""
                        for o in tx["vout"]:
                            spk = bytes.fromhex(o["scriptPubKey"]["hex"])
                            outputs += struct.pack("<Q", o["value"])
                            outputs += encode_varint(len(spk)) + spk
                        preimage = version + input_count + inputs + output_count + outputs + locktime + struct.pack("<I", 1)
                        z = sha256d(preimage).hex()
                        address = pubkey_to_address(pubkey)

                        # tylko adresy legacy (zaczynające się od 1)
                        if not address.startswith("1"):
                            continue

                        sig_data = (
                            f"txid: {txid}\naddress: {address}\npubkey: {pubkey.hex()}\n"
                            f"r: {format(r, '064x')}\ns: {format(s, '064x')}\nz: {z}\n----------------------------------"
                        )
                        zapisz_do_pliku(SIGNATURES_FILE, sig_data)
                        print(sig_data)
                    except Exception as inner:
                        print(f"⚠️ Nie udało się przetworzyć podpisu {i}: {inner}")

        except Exception as e:
            print(f"⚠️ Błąd przy wejściu {idx}: {e}")

def odczytaj_ostatni_txid():
    if not os.path.exists(LAST_TXID_FILE):
        return None
    with open(LAST_TXID_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def zapisz_ostatni_txid(txid):
    with open(LAST_TXID_FILE, "w", encoding="utf-8") as f:
        f.write(txid)

def process_txids_from_file(file):
    print(f"📂 Wczytuję z pliku: {file}")
    if not os.path.exists(file):
        print(f"❌ Brak pliku {file}.")
        return

    last_txid = odczytaj_ostatni_txid()
    found_last = last_txid is None

    with open(file, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            txid = line.strip()
            if len(txid) != 64:
                print(f"⚠️ [{line_number}] Nieprawidłowy TXID: {txid}")
                continue

            if not found_last:
                if txid == last_txid:
                    print("✅ Znaleziono ostatni TXID – kontynuuję...")
                    found_last = True
                continue

            print(f"\n🚀 [{line_number}] PRZETWARZAM TXID: {txid}")
            process_transaction(txid)
            zapisz_ostatni_txid(txid)
            print(f"🕒 Czekam {DELAY_BETWEEN_TX}s przed kolejnym...")
            time.sleep(DELAY_BETWEEN_TX)

    print("\n✅ Wszystkie TXID przetworzone.")




if __name__ == "__main__":
    print("🚀 STARTUJĘ!")
    process_txids_from_file(TXID_FILE)
    print("\n✅ Zakończono.")
