# 🧾 Bitcoin Transaction Signature Extractor & Analyzer

> ⚙️ **Advanced Bitcoin transaction decoder and ECDSA signature extractor**  
> This tool fetches raw Bitcoin transactions from multiple APIs,  
> decodes input scripts, extracts public keys and signatures,  
> reconstructs signing preimages, and computes the `z` hash used in ECDSA verification.

---

## 🚀 Overview

This program automates the process of:
- 🌐 Downloading raw transactions from up to 5 APIs (Blockstream, Blockchain.info, BlockCypher, SoChain, Mempool.space)
- 🔍 Decoding transaction structure (`vin`, `vout`, `scriptSig`)
- 🔑 Extracting **signatures** and **public keys** from standard P2PKH inputs
- 🧮 Deriving the **r, s, z** parameters used in the ECDSA verification process
- 🏷️ Reconstructing Bitcoin addresses from public keys
- 💾 Saving all extracted signature data to `signatures.txt`

---

## ✨ Features

| Feature | Description |
|----------|--------------|
| 🌐 **Multi-API fallback** | Tries 5 different public endpoints for each TXID |
| 🔑 **Signature & pubkey extraction** | Detects valid DER signatures and public keys |
| 🧮 **ECDSA parameter decoding** | Parses `r`, `s` and computes `z` double-SHA256 hash |
| 💾 **Data logging** | Saves all extracted info (TXID, address, pubkey, r, s, z) to file |
| 📦 **Resumable scanning** | Automatically resumes from the last processed TXID |
| 🧠 **Realistic Bitcoin TX parsing** | Decodes real transaction structures in raw hexadecimal format |
| ⏱️ **Rate limiting** | Configurable delay between API calls to prevent blocking |

---

## 📂 File Structure

| File | Description |
|------|-------------|
| `extract_signatures.py` | Main script |
| `txids.txt` | Input file containing TXIDs (one per line) |
| `signatures.txt` | Output file with extracted signature data |
| `last_txid.txt` | Auto-saved progress tracker for resuming |
| `README.md` | This documentation file |

---

## ⚙️ Configuration

| Variable | Description | Default |
|-----------|--------------|----------|
| `TXID_FILE` | Path to file with TXIDs to process | `txids.txt` |
| `SIGNATURES_FILE` | Output file for signature data | `signatures.txt` |
| `LAST_TXID_FILE` | File used for resuming last progress | `last_txid.txt` |
| `RAW_TX_APIS` | List of public Bitcoin APIs | 5 APIs |
| `USER_AGENTS` | Randomly rotated headers for realism | 3 values |
| `DELAY_BETWEEN_TX` | Delay between transactions (in seconds) | `3` |
| `MAX_RETRIES` | Maximum retries per API before skipping | `3` |

---

## 🧠 How It Works

### 1️⃣ Fetch Transaction Hex
The script attempts to download a transaction’s raw hex from multiple APIs:
```python
raw_tx = fetch_raw_tx(txid)
If all fail, it retries up to 3 times with randomized delays and UA rotation.

2️⃣ Decode Raw Transaction

The raw hexadecimal transaction is parsed into structured data (vin, vout, etc.)
using custom functions that handle Bitcoin’s varint encoding and endian order.

tx = zdekoduj_transakcje(raw_tx)

3️⃣ Extract Signatures and Public Keys

Each input’s scriptSig is parsed for pushdata operations.
If a valid DER signature followed by a compressed/uncompressed public key is found,
the script extracts and decodes them.

parts = parse_pushdata(script_bytes)
r, s = util.sigdecode_der(sig_candidate[:-1], SECP256k1.order)

4️⃣ Compute Signing Hash (z)

The script reconstructs the preimage used for signing —
combining transaction version, inputs, outputs, locktime, and sighash flag —
and applies a double SHA-256 hash:

preimage = version + inputs + outputs + locktime + struct.pack("<I", 1)
z = sha256d(preimage).hex()

5️⃣ Convert Public Key → Address

The extracted public key is hashed (SHA256 → RIPEMD160)
and Base58Check encoded to derive the associated legacy Bitcoin address:

address = pubkey_to_address(pubkey)


Only addresses starting with 1 (P2PKH) are saved.

6️⃣ Save Results

Each successfully processed signature is written to signatures.txt:

txid: 20c1bb76b0b82527fd4d948ab8ae14895f60ff80fb71ed05dd022da64247dfac
address: 1JZkeMzeWG2ioZp2sFcrQ3pHCYMva8aGMj
pubkey: 02174ee672429ff94304321cdae1fc1e487edf658b34bd1d36da03761658a2bb09
r: 6216579c3aa0801a7cc327e96a980549b5a3df1903fa21ab100f5bdc2d138bbe
s: 7f0eda2c46dffebfd8fb630878eba1a7b46b0a8f2afc6762ff3e253abfa267bc
z: 58d5a7c8ff3cf4c9b18ed7c96c514f701ac63c3f0b7a4c8b8da9f6c1dfef2447
----------------------------------

🧩 Core Functions
Function	Description
fetch_raw_tx()	Downloads transaction data from up to 5 APIs
zdekoduj_transakcje()	Parses the binary structure of a Bitcoin transaction
parse_pushdata()	Splits scriptSig bytes into individual pushdata items
pubkey_to_address()	Converts a raw pubkey to a Base58 legacy address
process_transaction()	Orchestrates decoding and signature extraction
process_txids_from_file()	Processes all TXIDs from a text file, resuming if interrupted
⚡ Performance Notes

⏱️ Recommended delay: 2–3 seconds between TXIDs to avoid API bans.

🔁 The script automatically skips unreachable APIs after repeated failures.

🧩 Use smaller TXID batches for large datasets.

💾 You can resume processing using last_txid.txt.

🔒 Ethical & Legal Notice

This script is strictly for blockchain analysis and cryptographic education.
It does not access private keys, alter transactions, or broadcast any data.

You may:

Study Bitcoin’s ECDSA signing process.

Audit or research transaction structures.

Build analytics for public blockchain data.

You must not:

Use it for privacy-invasive or malicious scraping.

Analyze or re-sign other users’ transactions without consent.

Respect the Bitcoin network and applicable laws. ⚖️

🧰 Suggested Improvements

🧮 Add support for SegWit (witness-based) inputs.

💾 Export extracted data as JSON or CSV.

🔁 Include automatic retries with exponential backoff.

⚙️ Implement multiprocessing for bulk TXID scans.

📊 Add progress tracking and performance metrics.

🪪 License

MIT License
© 2025 — Author: [Ethicbrudhack]

💡 Summary

This project is a powerful forensic tool for exploring Bitcoin transaction internals —
perfect for researchers, security experts, and cryptography enthusiasts.

It showcases the full ECDSA data pipeline:

TXID → Raw Hex → Decoded Inputs → Signature (r,s,z) → Derived Address

🧠 Knowledge is the strongest encryption. — [Ethicbrudhack]

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
