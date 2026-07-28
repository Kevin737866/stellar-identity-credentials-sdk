#!/bin/bash
set -e

echo "Starting local Soroban sandbox (Stellar Quickstart)..."
# Starts the stellar quickstart image in local mode with a fresh ledger
docker run -d \
  -p 8000:8000 \
  -p 11626:11626 \
  -p 11625:11625 \
  --name soroban-sandbox \
  stellar/quickstart:latest \
  --local \
  --enable-soroban-rpc

echo "Waiting for sandbox to initialize..."
sleep 5

echo "Sandbox is running!"
echo "RPC Server: http://localhost:8000/soroban/rpc"
echo "Network Passphrase: 'Standalone Network ; February 2017'"
