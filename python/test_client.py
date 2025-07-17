#!/usr/bin/env python3
"""
Test script for schwab-proxy using the monkeypatched schwab-py client.

This script:
1. Patches schwab-py to use the local proxy
2. Performs OAuth authentication through the proxy
3. Makes various API calls to test the proxy functionality

Usage:
    python test_client.py [--proxy-url https://localhost:8080] [--app-key YOUR_KEY] [--app-secret YOUR_SECRET]
"""

import argparse
import json
import os
import sys
from pathlib import Path

# CRITICAL: Patch BEFORE importing any schwab modules
import schwab_monkeypatch


def test_api_calls(client):
    """Test various API endpoints through the proxy"""
    print("\n" + "=" * 60)
    print("TESTING API CALLS THROUGH PROXY")
    print("=" * 60)

    tests = []

    # Initialize account_hash for later tests
    account_hash = None
    
    # Helper function to handle 401 errors
    def make_request_with_retry(request_func, *args, **kwargs):
        """Make a request and retry once if we get a 401"""
        response = request_func(*args, **kwargs)
        
        if response.status_code == 401:
            print("      Got 401, attempting to refresh token...")
            try:
                # Manually refresh the token
                if hasattr(client, 'session') and hasattr(client.session, 'refresh_token'):
                    # Get the token endpoint from the patched auth module
                    import schwab
                    token_endpoint = schwab.auth.TOKEN_ENDPOINT
                    
                    # Get current token
                    if hasattr(client.session, 'token') and client.session.token:
                        refresh_token = client.session.token.get('refresh_token')
                        if refresh_token:
                            print("      Refreshing token...")
                            client.session.refresh_token(token_endpoint, refresh_token=refresh_token)
                            print("      Token refreshed successfully")
                        else:
                            print("      No refresh token available")
                
                # Retry the request
                response = request_func(*args, **kwargs)
                
                if response.status_code == 401:
                    print("      Still got 401 after token refresh.")
                    print("      Try deleting the token file and re-authenticating.")
            except Exception as e:
                print(f"      Failed to refresh token: {e}")
            
        return response

    # Test 1: Account Numbers (no parameters required)
    print("\n1. Testing get_account_numbers()...")
    try:
        response = make_request_with_retry(client.get_account_numbers)
        print(f"   ✓ Success: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
            tests.append(("get_account_numbers", True, response.status_code))
            # Store account hash for later tests
            if data and len(data) > 0:
                account_hash = data[0].get("hashValue")
                print(f"   Account hash for later tests: {account_hash}")
        else:
            tests.append(("get_account_numbers", False, response.status_code))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("get_account_numbers", False, str(e)))

    # Test 2: User Preferences (no parameters required)
    print("\n2. Testing get_user_preferences()...")
    try:
        response = make_request_with_retry(client.get_user_preferences)
        print(f"   ✓ Success: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
        tests.append(
            ("get_user_preferences", response.status_code == 200, response.status_code)
        )
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("get_user_preferences", False, str(e)))

    # Test 3: All Accounts
    print("\n3. Testing get_accounts()...")
    try:
        response = make_request_with_retry(client.get_accounts)
        print(f"   ✓ Success: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
        tests.append(
            ("get_accounts", response.status_code == 200, response.status_code)
        )
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("get_accounts", False, str(e)))

    # Test 4: Single Stock Quote
    print("\n4. Testing get_quote('AAPL')...")
    try:
        response = make_request_with_retry(client.get_quote, "AAPL")
        print(f"   ✓ Success: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            # Just show a subset since quotes can be large
            if "AAPL" in data:
                quote_response = data["AAPL"]
                # The actual quote data is nested inside the 'quote' field
                if "quote" in quote_response:
                    quote = quote_response["quote"]
                    print(f"   AAPL Last Price: {quote.get('lastPrice', 'N/A')}")
                    print(
                        f"   AAPL Bid/Ask: {quote.get('bidPrice', 'N/A')}/{quote.get('askPrice', 'N/A')}"
                    )
                else:
                    print("   No 'quote' field found in response")
                    print(f"   Available fields: {list(quote_response.keys())}")
        tests.append(("get_quote", response.status_code == 200, response.status_code))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("get_quote", False, str(e)))

    # Test 5: Multiple Stock Quotes
    print("\n5. Testing get_quotes(['AAPL', 'GOOGL', 'MSFT'])...")
    try:
        response = make_request_with_retry(client.get_quotes, ["AAPL", "GOOGL", "MSFT"])
        print(f"   ✓ Success: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            for symbol in ["AAPL", "GOOGL", "MSFT"]:
                if symbol in data:
                    quote_response = data[symbol]
                    # The actual quote data is nested inside the 'quote' field
                    if "quote" in quote_response:
                        quote = quote_response["quote"]
                        print(
                            f"   {symbol} Last Price: {quote.get('lastPrice', 'N/A')}"
                        )
                    else:
                        print(f"   {symbol}: No 'quote' field found")
        tests.append(("get_quotes", response.status_code == 200, response.status_code))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("get_quotes", False, str(e)))

    # Test 6: Market Hours
    print("\n6. Testing get_market_hours(['equity'])...")
    try:
        # Use the correct Market enum from client.MarketHours.Market
        response = make_request_with_retry(client.get_market_hours, [client.MarketHours.Market.EQUITY])
        print(f"   ✓ Success: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
        tests.append(
            ("get_market_hours", response.status_code == 200, response.status_code)
        )
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("get_market_hours", False, str(e)))

    # Test 7: Account-specific call (if we have an account hash)
    if account_hash:
        print(f"\n7. Testing get_account('{account_hash}')...")
        try:
            response = make_request_with_retry(client.get_account, account_hash)
            print(f"   ✓ Success: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                # Show basic account info without sensitive details
                if "securitiesAccount" in data:
                    account = data["securitiesAccount"]
                    print(f"   Account Type: {account.get('type', 'N/A')}")
                    print(
                        f"   Account Value: {account.get('currentBalances', {}).get('liquidationValue', 'N/A')}"
                    )
            tests.append(
                ("get_account", response.status_code == 200, response.status_code)
            )
        except Exception as e:
            print(f"   ✗ Error: {e}")
            tests.append(("get_account", False, str(e)))
    else:
        print("\n7. Skipping get_account() - no account hash available")
        tests.append(("get_account", False, "No account hash"))

    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, success, _ in tests if success)
    total = len(tests)
    print(f"Passed: {passed}/{total}")
    print("\nDetailed Results:")
    for test_name, success, result in tests:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status:<8} {test_name:<20} {result}")

    return passed == total


def main():
    parser = argparse.ArgumentParser(
        description="Test schwab-proxy with monkeypatched schwab-py client"
    )
    parser.add_argument(
        "--proxy-url",
        default="https://localhost:8080",
        help="Proxy server URL (default: https://localhost:8080)",
    )
    parser.add_argument(
        "--app-key", help="Schwab app key (or set SCHWAB_APP_KEY env var)"
    )
    parser.add_argument(
        "--app-secret", help="Schwab app secret (or set SCHWAB_APP_SECRET env var)"
    )
    parser.add_argument(
        "--token-file",
        default="schwab_token.json",
        help="Token file path (default: schwab_token.json)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL verification for self-signed certificates",
    )

    args = parser.parse_args()

    # Get credentials
    app_key = args.app_key or os.getenv("SCHWAB_APP_KEY")
    app_secret = args.app_secret or os.getenv("SCHWAB_APP_SECRET")

    if not app_key or not app_secret:
        print(
            "Error: Must provide app key and secret via --app-key/--app-secret or SCHWAB_APP_KEY/SCHWAB_APP_SECRET env vars"
        )
        return 1

    print("Schwab Proxy Test Client")
    print("=" * 50)
    print(f"Proxy URL: {args.proxy_url}")
    print(f"Token file: {args.token_file}")
    print(f"SSL verification: {'Disabled' if args.no_verify_ssl else 'Enabled'}")

    # Step 1: Patch the client BEFORE importing schwab
    print("\n1. Patching schwab-py client to use proxy...")
    schwab_monkeypatch.patch_schwab_client(
        args.proxy_url, verify_ssl=not args.no_verify_ssl
    )

    # Step 2: NOW we can safely import schwab modules
    print("\n2. Importing schwab modules...")
    try:
        import schwab
    except ImportError:
        print("Error: schwab-py package not found. Install with: pip install schwab-py")
        return 1

    # Step 3: Handle SSL verification
    if args.no_verify_ssl:
        print("\n3. Disabling SSL verification for self-signed certificates...")
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        import ssl

        # Disable SSL verification globally
        ssl._create_default_https_context = ssl._create_unverified_context
        # Also set environment variable for requests/httpx
        os.environ["PYTHONHTTPSVERIFY"] = "0"
        os.environ["CURL_CA_BUNDLE"] = ""

    # Step 4: Set up authentication
    print("\n4. Setting up authentication...")
    token_path = Path(args.token_file)

    if token_path.exists():
        print(f"   Found existing token file: {token_path}")
        # Load existing token
        try:
            # Use schwab-py's native token loading method
            client = schwab.auth.client_from_token_file(
                token_path=token_path, api_key=app_key, app_secret=app_secret
            )
            print("   ✓ Loaded existing token")
        except Exception as e:
            print(f"   ✗ Failed to load token: {e}")
            print("   Please delete the token file and re-run to re-authenticate")
            return 1
    else:
        print("   No token file found. Starting OAuth flow...")
        print(f"   NOTE: OAuth will go through the proxy at {args.proxy_url}")

        try:
            # This will use the patched OAuth endpoints (proxy's OAuth server)
            client = schwab.auth.client_from_login_flow(
                api_key=app_key,
                app_secret=app_secret,
                callback_url="https://127.0.0.1:3000",  # Test client callback, not proxy callback
                token_path=token_path,
            )
            print("   ✓ OAuth flow completed successfully")
        except Exception as e:
            print(f"   ✗ OAuth flow failed: {e}")
            import traceback

            traceback.print_exc()
            return 1

    # Step 5: Test API calls
    try:
        success = test_api_calls(client)
        if success:
            print("\n🎉 All tests passed! The proxy is working correctly.")
            return 0
        else:
            print("\n❌ Some tests failed. Check the proxy server logs.")
            return 1
    except Exception as e:
        print(f"\n💥 Test execution failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
