#!/bin/bash

# LLM Tool-Use Exploit Demo Script
# Demonstrates baseline vs defended modes

set -e

echo "=========================================="
echo "LLM Tool-Use Exploit Demo"
echo "=========================================="
echo

# Ensure we're in the project root
cd "$(dirname "$0")/.."

echo "1. Running BASELINE mode (unguarded tools)..."
echo "   Input: exploits/malicious_input.md"
echo "   Expected: Malicious send_to should execute"
echo

python run.py --mode baseline --input exploits/malicious_input.md

echo
echo "2. Running DEFENDED mode (policy + audit)..."
echo "   Input: exploits/malicious_input.md"
echo "   Expected: Malicious send_to should be BLOCKED"
echo

python run.py --mode defended --input exploits/malicious_input.md

echo
echo "3. Checking audit log for blocked exfiltration..."
echo "   Looking for BLOCK decision in audit.jsonl"
echo

if [ -f "logs/audit.jsonl" ]; then
    echo "Audit log contents:"
    cat logs/audit.jsonl | jq -r '.decision + " - " + .tool + " - " + .reason' 2>/dev/null || cat logs/audit.jsonl
    echo
    
    # Check for blocked send_to
    if grep -q '"decision":"BLOCK"' logs/audit.jsonl; then
        echo "✅ SUCCESS: Found BLOCK decision in audit log"
        if grep -q 'attacker.local' logs/audit.jsonl; then
            echo "✅ SUCCESS: Blocked exfiltration to attacker.local"
        fi
    else
        echo "❌ FAILURE: No BLOCK decision found in audit log"
    fi
else
    echo "❌ FAILURE: Audit log not found"
fi

echo
echo "4. Checking egress log for baseline mode..."
echo "   Looking for simulated exfiltration in egress.log"
echo

if [ -f "logs/egress.log" ]; then
    echo "Egress log contents:"
    cat logs/egress.log
    echo
    
    if grep -q 'attacker.local' logs/egress.log; then
        echo "✅ SUCCESS: Found exfiltration attempt in egress log (baseline mode)"
    else
        echo "❌ FAILURE: No exfiltration found in egress log"
    fi
else
    echo "❌ FAILURE: Egress log not found"
fi

echo
echo "5. Running audit chain validation..."
echo "   Validating tamper-evident audit chain"
echo

python -c "
from audit.log import validate_chain
from pathlib import Path
import sys

audit_log = Path('logs/audit.jsonl')
if audit_log.exists():
    is_valid = validate_chain(audit_log)
    if is_valid:
        print('✅ SUCCESS: Audit chain is valid')
    else:
        print('❌ FAILURE: Audit chain validation failed')
        sys.exit(1)
else:
    print('❌ FAILURE: Audit log not found')
    sys.exit(1)
"

echo
echo "=========================================="
echo "Demo completed successfully!"
echo "=========================================="
echo
echo "Summary:"
echo "- Baseline mode: Malicious exfiltration executed (simulated)"
echo "- Defended mode: Malicious exfiltration blocked by policy"
echo "- Audit trail: Tamper-evident hash chain validated"
echo "- Policy enforcement: Single choke point working correctly"
