# Bitcoin Blockchain Explorer

**Author**: Isaac Yushaiyin  


## 📌 Description

This project implements a **Bitcoin Blockchain Explorer** using the Bitcoin P2P protocol. It connects to a real Bitcoin node via TCP/IP, retrieves a historical block, decodes and displays its transactions, and demonstrates how modifying blockchain data invalidates the chain.

The entire protocol logic is written from scratch in Python 3 — **without using any third-party Bitcoin libraries** — in accordance with academic requirements.

---

## 🚀 Features

- **Message Construction & Parsing**  
  Implements low-level Bitcoin P2P message types including `version`, `getblocks`, `getdata`, `ping`, etc.

- **Block & Transaction Retrieval**  
  Connects to a full Bitcoin node, downloads historical blocks and parses transaction input/output fields.

- **Experimental Block Modification**  
  Modifies transaction output value in a block, recalculates Merkle root and block hash, and shows how the next block will reject the tampered block.

- **Blockchain Integrity Validation**  
  Displays side-by-side comparison of original and modified block metadata (hashes, Merkle roots, etc.).

- **No Libraries Used**  
  Fully implemented using only Python 3 standard libraries (e.g., `socket`, `hashlib`).

---

## 🧠 Concepts Demonstrated

- Distributed systems & peer-to-peer communication
- TCP/IP socket programming
- Blockchain data structure (blocks, transactions, Merkle tree)
- SHA-256 hashing and integrity validation
- Endianness handling
- CompactSize and binary message formats

---

## 🛠️ Usage Instructions

1. **Ensure you are using Python 3.**
2. Run the script with a valid block number:

```bash
python3 lab5.py 5122
```

> ⚠️ For performance and safety, please use a small block number (under 10,000). Large blocks take a long time to process.

---

## 🧪 Example Output

- Successfully connects to a Bitcoin full node
- Downloads a specific block and displays decoded transaction data
- Changes a transaction value, updates Merkle root and block hash
- Verifies that the altered block is rejected by the next block

---

## 🔗 Third-Party Files & Attribution

This project uses the following external files solely for peer discovery:

- **`makeseeds.py` and `asmap.py`**  
  → Source: https://github.com/sipa/bitcoin-seeder  
  → Author: Pieter Wuille  
  → License: MIT

- **`asmap-filled.dat` and `seeds_main.txt`**  
  → Downloaded from: https://bitcoin.sipa.be/seeds.txt.gz  
  → Purpose: Used to find active Bitcoin nodes (not involved in blockchain parsing).

> These are attribution-only utilities. **All Bitcoin parsing logic was implemented independently in `lab5.py`**.

---

## ✅ Requirements

- Python 3.x
- Internet access (to connect to live Bitcoin node)
- Node IP selected from `nodes_main.txt`

---

## 📘 References

- [Bitcoin Developer Guide](https://developer.bitcoin.org/devguide/p2p_network.html)
- [Bitcoin P2P Protocol](https://en.bitcoin.it/wiki/Protocol_documentation)
- [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf)

---

## 📄 License

This project is developed for academic purposes. External attribution files follow the MIT License as defined in their original repositories.

