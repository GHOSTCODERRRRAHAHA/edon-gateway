# EDON Gateway Quick Start

## Server is Running! ✅

Your gateway is running on `http://localhost:8000`

## Test the Gateway

### Option 1: Use the Test Script

In a **new terminal** (keep the server running):

```bash
# Install requests if needed
pip install requests

# Run test script
python edon_gateway/test_gateway.py
```

### Option 2: Manual Testing with curl

```bash
# Health check
curl http://localhost:8000/health

# Set intent
curl -X POST http://localhost:8000/intent/set \
  -H "Content-Type: application/json" \
  -d '{
    "objective": "Manage inbox. Drafts only.",
    "scope": {"email": ["draft"], "calendar": ["view"]},
    "constraints": {"drafts_only": true, "max_recipients": 3},
    "risk_level": "low",
    "approved_by_user": true
  }'

# Execute action (replace INTENT_ID from previous response)
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "action": {
      "tool": "email",
      "op": "draft",
      "params": {
        "recipients": ["user@example.com"],
        "subject": "Test",
        "body": "Body"
      }
    },
    "intent_id": "INTENT_ID",
    "agent_id": "clawdbot-001"
  }'
```

### Option 3: Use the SDK

```python
from edon_guard_sdk import EDONClient, ActionBlockedError

client = EDONClient(
    gateway_url="http://localhost:8000",
    agent_id="clawdbot-001"
)

# Set intent
intent_id = client.set_intent(
    objective="Manage inbox. Drafts only.",
    scope={"email": ["draft"]},
    constraints={"drafts_only": True}
)

# Execute action
try:
    result = client.execute(
        tool="email",
        op="draft",
        params={"recipients": ["user@example.com"], "subject": "Test", "body": "Body"},
        intent_id=intent_id
    )
    print(f"Success: {result['verdict']}")
except ActionBlockedError as e:
    print(f"Blocked: {e}")
```

## Next Steps

1. **Test all endpoints** - Run the test script to verify everything works
2. **Create real tool connectors** - Replace mock execution with real email/shell connectors
3. **Integration test** - Test Clawdbot SDK → Gateway → Tool end-to-end

## Troubleshooting

### Import Error: `edon_demo` not found

Make sure you're running from the project root:
```bash
cd C:\Users\cjbig\Desktop\EDON\edon-cav-engine
python -m edon_gateway.main
```

### Port 8000 already in use

Change the port in `edon_gateway/main.py`:
```python
uvicorn.run(app, host="0.0.0.0", port=8001)  # Use 8001 instead
```

### Gateway not responding

Check that the server is running and check the logs for errors.
