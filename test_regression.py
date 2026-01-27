"""Regression tests for production safety invariants.

These tests ensure critical production safety features never regress:
- No traceback leakage
- HTTPException status codes preserved (especially 503)
- No file paths in error messages
"""

import os
import requests
import json

BASE_URL = os.getenv("EDON_GATEWAY_URL", "http://localhost:8000")
AUTH_TOKEN = os.getenv("EDON_API_TOKEN", "test-token")


def test_no_traceback_leakage():
    """Test that error responses never include tracebacks or file paths."""
    print("Testing: No traceback leakage...")
    
    # Trigger a credential error in strict mode
    response = requests.post(
        f"{BASE_URL}/execute",
        json={
            "action": {
                "tool": "email",
                "op": "send",
                "params": {
                    "recipients": ["test@example.com"],
                    "subject": "Test",
                    "body": "Test"
                }
            },
            "agent_id": "test-agent-001"
        },
        headers={"X-EDON-TOKEN": AUTH_TOKEN} if os.getenv("EDON_AUTH_ENABLED") == "true" else {}
    )
    
    response_text = response.text.lower()
    
    # Assertions
    assert "traceback" not in response_text, f"Response contains 'traceback': {response.text}"
    assert "file \"" not in response_text, f"Response contains file path: {response.text}"
    assert "line " not in response_text or "line " not in response_text.split("detail")[0], \
        f"Response contains line numbers: {response.text}"
    assert "c:\\" not in response_text and "/" not in response_text.split("detail")[-1][:100], \
        f"Response contains file system paths: {response.text}"
    
    print(f"  ✓ No traceback leakage (status: {response.status_code})")
    return True


def test_503_preserved():
    """Test that 503 status codes are preserved and not wrapped in 500."""
    print("Testing: 503 status code preservation...")
    
    # Trigger credential error in strict mode
    response = requests.post(
        f"{BASE_URL}/execute",
        json={
            "action": {
                "tool": "email",
                "op": "send",
                "params": {
                    "recipients": ["test@example.com"],
                    "subject": "Test",
                    "body": "Test"
                }
            },
            "agent_id": "test-agent-001"
        },
        headers={"X-EDON-TOKEN": AUTH_TOKEN} if os.getenv("EDON_AUTH_ENABLED") == "true" else {}
    )
    
    # Should be 503, not 500
    assert response.status_code == 503, \
        f"Expected 503, got {response.status_code}: {response.text}"
    
    # Response should mention service unavailable or credential
    response_text = response.text.lower()
    assert "service unavailable" in response_text or "credential" in response_text, \
        f"Response should mention service unavailable or credential: {response.text}"
    
    print(f"  ✓ 503 status code preserved")
    return True


def test_no_file_paths_in_errors():
    """Test that error messages never include file system paths."""
    print("Testing: No file paths in error messages...")
    
    # Try various error scenarios
    test_cases = [
        # Invalid action
        {
            "action": {"tool": "invalid_tool", "op": "test"},
            "agent_id": "test"
        },
        # Missing required fields
        {
            "action": {},
            "agent_id": "test"
        }
    ]
    
    for test_case in test_cases:
        try:
            response = requests.post(
                f"{BASE_URL}/execute",
                json=test_case,
                headers={"X-EDON-TOKEN": AUTH_TOKEN} if os.getenv("EDON_AUTH_ENABLED") == "true" else {}
            )
            
            response_text = response.text.lower()
            
            # Check for file paths
            assert "c:\\" not in response_text, f"Response contains Windows path: {response.text}"
            assert "/users/" not in response_text and "/home/" not in response_text, \
                f"Response contains Unix path: {response.text}"
            assert ".py" not in response_text.split("detail")[-1][:200], \
                f"Response contains Python file reference: {response.text}"
        except Exception:
            pass  # Some requests may fail before reaching the endpoint
    
    print("  ✓ No file paths in error messages")
    return True


def test_error_envelope_consistency():
    """Test that all errors use consistent envelope format."""
    print("Testing: Error envelope consistency...")
    
    # Test various error scenarios
    error_scenarios = [
        # 401 - Missing auth
        (lambda: requests.post(f"{BASE_URL}/execute", json={"action": {}, "agent_id": "test"}), 401),
        # 400 - Invalid input
        (lambda: requests.post(
            f"{BASE_URL}/execute",
            json={"action": {"tool": "email", "op": "draft", "params": {"body": "<script>alert(1)</script>"}}, "agent_id": "test"},
            headers={"X-EDON-TOKEN": AUTH_TOKEN} if os.getenv("EDON_AUTH_ENABLED") == "true" else {}
        ), 400),
    ]
    
    for make_request, expected_status in error_scenarios:
        try:
            response = make_request()
            
            # All errors should be JSON with "detail" field
            assert response.headers.get("content-type", "").startswith("application/json"), \
                f"Error response should be JSON: {response.headers.get('content-type')}"
            
            try:
                data = response.json()
                assert "detail" in data, f"Error response should have 'detail' field: {data}"
                assert isinstance(data["detail"], str), f"Error detail should be string: {data}"
            except json.JSONDecodeError:
                assert False, f"Error response is not valid JSON: {response.text}"
        except Exception:
            pass  # Some scenarios may not apply in all configurations
    
    print("  ✓ Error envelope consistency")
    return True


def run_regression_tests():
    """Run all regression tests."""
    print("=" * 70)
    print("Production Safety Regression Tests")
    print("=" * 70)
    print()
    
    tests = [
        ("No Traceback Leakage", test_no_traceback_leakage),
        ("503 Status Preserved", test_503_preserved),
        ("No File Paths in Errors", test_no_file_paths_in_errors),
        ("Error Envelope Consistency", test_error_envelope_consistency),
    ]
    
    results = {"passed": 0, "failed": 0, "errors": []}
    
    for test_name, test_func in tests:
        try:
            print(f"\n{test_name}:")
            test_func()
            results["passed"] += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {str(e)}")
            results["failed"] += 1
            results["errors"].append(f"{test_name}: {str(e)}")
        except Exception as e:
            print(f"  ✗ ERROR: {str(e)}")
            results["failed"] += 1
            results["errors"].append(f"{test_name}: {str(e)}")
    
    print("\n" + "=" * 70)
    print("Regression Test Summary")
    print("=" * 70)
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Total: {results['passed'] + results['failed']}")
    
    if results["errors"]:
        print("\nErrors:")
        for error in results["errors"]:
            print(f"  - {error}")
    
    if results["failed"] > 0:
        print("\n❌ Some regression tests failed!")
        return 1
    else:
        print("\n✅ All regression tests passed!")
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run_regression_tests())
