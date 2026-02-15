#!/bin/bash
# Deploy botsters using seksh-brokered CF token
# This script fetches the CF API token through the broker and passes it to wrangler

SEKSH="/Users/footgun/.seksbot/workspace/seksh/target/release/nu"
export SEKS_BROKER_URL="https://seks-broker.stcredzero.workers.dev"
export SEKS_AGENT_TOKEN="$(cat /Users/footgun/.seksbot/workspace/dropbox/seks-broker-agent-token)"

# Use seksh to inject the token into wrangler's environment
# getseks returns <secret:NAME> to shell but the actual value is available 
# in the scrub registry — we need a different approach

# Actually, we can use the CF API directly via seksh-http to upload the Worker
echo "Deploying via wrangler..."
cd /Users/footgun/.seksbot/workspace/botsters

# Get the token through a file descriptor trick
# seksh-http can make the deploy API call directly
$SEKSH -c "
  # We need to deploy via CF API, not wrangler CLI
  # Step 1: Build the worker bundle first
"
