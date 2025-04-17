# Bitcoin Blockchain Explorer

This project implements a lightweight Bitcoin Blockchain Explorer using the Bitcoin P2P protocol.  
It connects to a Bitcoin node, retrieves and parses blocks, analyzes transactions, and supports experimental modification of blockchain data.

## Features
- Retrieves 500+ blocks and 1,000+ transactions from live nodes
- Parses and validates Merkle roots and block hashes
- Simulates block tampering and shows integrity breakdown
- Implements custom message handling (e.g., `version`, `getblocks`, `getdata`)

## Technologies
- Python 3
- TCP Sockets
- SHA256, Merkle Tree logic

## Usage
1. Connect to a Bitcoin node via IP
2. Run the script: `python3 explorer.py`
3. View block, transaction, and hash data

## License
MIT
