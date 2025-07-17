#!/usr/bin/env python3
"""
Test script for schwab-proxy streaming functionality using schwab-py client.

This script tests:
1. WebSocket connection through the proxy
2. Streaming authentication
3. Subscription management (SUBS, ADD, UNSUBS)
4. Data message routing

Usage:
    python test_streaming.py --app-key YOUR_KEY --app-secret YOUR_SECRET --tickers AAPL,MSFT,GOOGL
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

# CRITICAL: Patch BEFORE importing any schwab modules
import schwab_monkeypatch


class StreamingTestClient:
    """Test client for streaming functionality"""

    def __init__(self, schwab_client, account_id: str):
        self.schwab_client = schwab_client
        self.account_id = account_id
        self.stream_client = None
        self.messages_received = 0
        self.subscribed_symbols: Set[str] = set()
        self.data_by_symbol: Dict[str, List[dict]] = {}
        self.errors: List[str] = []
        self.connected = False

    async def setup_streaming(self):
        """Initialize the streaming client"""
        from schwab.streaming import StreamClient

        self.stream_client = StreamClient(
            self.schwab_client,
            account_id=self.account_id
        )

        prefs_func = self.stream_client._client.get_user_preferences

        async def get_user_preferences():
            response = await prefs_func()
            
            # Handle 401 - try to refresh token once
            if response.status_code == 401:
                print("   Got 401 on user preferences, attempting to refresh token...")
                try:
                    # Manually refresh the token
                    if hasattr(self.schwab_client, 'session') and hasattr(self.schwab_client.session, 'refresh_token'):
                        # Get the token endpoint from the patched auth module
                        import schwab
                        token_endpoint = schwab.auth.TOKEN_ENDPOINT
                        
                        # Get current token
                        if hasattr(self.schwab_client.session, 'token') and self.schwab_client.session.token:
                            refresh_token = self.schwab_client.session.token.get('refresh_token')
                            if refresh_token:
                                print("   Refreshing token...")
                                await self.schwab_client.session.refresh_token(token_endpoint, refresh_token=refresh_token)
                                print("   Token refreshed successfully")
                                # Retry the request
                                response = await prefs_func()
                except Exception as e:
                    print(f"   Failed to refresh token: {e}")
                
            print(f"User preferences response: {response.json()}")
            return response

        # Patch the client to use the custom get_user_preferences
        self.stream_client._client.get_user_preferences = get_user_preferences

        # Add handlers for different data types
        self.stream_client.add_level_one_equity_handler(
            lambda msg: self._handle_level_one_equity(msg)
        )

        print("StreamClient initialized")
        return True

    async def connect_and_login(self):
        """Connect to the WebSocket and login"""
        print("Attempting to login to stream...")
        await self.stream_client.login()
        self.connected = True
        print("✓ Successfully logged in to stream")
        return True

    async def subscribe_to_symbols(self, symbols: List[str]):
        """Subscribe to level 1 equity data for given symbols"""
        print(f"Subscribing to symbols: {symbols}")
        await self.stream_client.level_one_equity_subs(symbols)
        self.subscribed_symbols.update(symbols)
        print(f"✓ Subscribed to {len(symbols)} symbols")
        return True

    async def add_symbols(self, symbols: List[str]):
        """Add additional symbols to subscription"""
        print(f"Adding symbols: {symbols}")
        await self.stream_client.level_one_equity_add(symbols)
        self.subscribed_symbols.update(symbols)
        print(f"✓ Added {len(symbols)} symbols")
        return True

    async def unsubscribe_symbols(self, symbols: List[str]):
        """Unsubscribe from specific symbols"""
        print(f"Unsubscribing from symbols: {symbols}")
        await self.stream_client.level_one_equity_unsubs(symbols)
        self.subscribed_symbols.difference_update(symbols)
        print(f"✓ Unsubscribed from {len(symbols)} symbols")
        return True

    async def handle_messages(self, duration: int = 30):
        """Handle incoming messages for specified duration"""
        print(f"Starting message handler for {duration} seconds...")
        start_time = time.time()

        try:
            while time.time() - start_time < duration:
                await self.stream_client.handle_message()
                await asyncio.sleep(0.01)  # Small delay to prevent tight loop
        except asyncio.CancelledError:
            print("Message handler cancelled")
            raise

    def _handle_level_one_equity(self, msg):
        """Handler for level 1 equity data"""
        self.messages_received += 1

        # Extract symbol from message
        symbol = msg.get('key', 'UNKNOWN')

        # Store message data
        if symbol not in self.data_by_symbol:
            self.data_by_symbol[symbol] = []

        self.data_by_symbol[symbol].append({
            'timestamp': datetime.now().isoformat(),
            'data': msg
        })

        # Print first few messages for debugging
        if self.messages_received <= 5:
            print(f"Received data for {symbol}: {json.dumps(msg, indent=2)}")
        elif self.messages_received % 10 == 0:
            print(f"Total messages received: {self.messages_received}")

    def get_summary(self):
        """Get summary of test results"""
        return {
            'connected': self.connected,
            'messages_received': self.messages_received,
            'symbols_subscribed': len(self.subscribed_symbols),
            'symbols_with_data': len(self.data_by_symbol),
            'errors': len(self.errors),
            'error_details': self.errors
        }


async def test_streaming(schwab_client, account_id, tickers, duration):
    """Test streaming with specified tickers"""
    print("\n" + "="*60)
    print("STREAMING TEST")
    print("="*60)

    client = StreamingTestClient(schwab_client, account_id)

    # Setup streaming
    await client.setup_streaming()

    # Connect and login
    await client.connect_and_login()

    # Subscribe to specified tickers
    print(f"\nSubscribing to tickers: {tickers}")
    await client.subscribe_to_symbols(tickers)

    # Handle messages for specified duration
    print(f"\nStreaming data for {duration} seconds...")
    await client.handle_messages(duration)

    # Print summary
    summary = client.get_summary()
    print("\n" + "-"*40)
    print("STREAMING TEST SUMMARY")
    print("-"*40)
    print(f"Connected: {summary['connected']}")
    print(f"Messages received: {summary['messages_received']}")
    print(f"Symbols subscribed: {summary['symbols_subscribed']}")
    print(f"Symbols with data: {summary['symbols_with_data']}")

    # Show data summary per symbol
    if client.data_by_symbol:
        print("\nData received per symbol:")
        for symbol, data in client.data_by_symbol.items():
            print(f"  {symbol}: {len(data)} messages")




async def main_async(args):
    """Main async function"""
    # Get credentials
    app_key = args.app_key or os.getenv("SCHWAB_APP_KEY")
    app_secret = args.app_secret or os.getenv("SCHWAB_APP_SECRET")

    if not app_key or not app_secret:
        print("Error: Must provide app key and secret (via --app-key/--app-secret or SCHWAB_APP_KEY/SCHWAB_APP_SECRET env vars)")
        return 1

    # Parse tickers
    tickers = [t.strip().upper() for t in args.tickers.split(",") if t.strip()]
    if not tickers:
        print("Error: Must provide at least one ticker")
        return 1

    print("Schwab Proxy Streaming Test")
    print("="*50)
    print(f"Proxy URL: {args.proxy_url}")
    print(f"SSL verification: {'Disabled' if args.no_verify_ssl else 'Enabled'}")
    print(f"Tickers to monitor: {', '.join(tickers)}")
    print(f"Stream duration: {args.stream_duration} seconds")

    # Patch schwab client
    print("\n1. Patching schwab-py client to use proxy...")
    schwab_monkeypatch.patch_schwab_client(
        args.proxy_url, verify_ssl=not args.no_verify_ssl
    )

    # Import schwab after patching
    print("\n2. Importing schwab modules...")
    import schwab

    # Handle SSL
    if args.no_verify_ssl:
        print("\n3. Disabling SSL verification...")
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        import ssl
        ssl._create_default_https_context = ssl._create_unverified_context
        os.environ["PYTHONHTTPSVERIFY"] = "0"
        os.environ["CURL_CA_BUNDLE"] = ""

    # Create client
    print("\n4. Creating Schwab client...")
    token_path = Path(args.token_file)

    if token_path.exists():
        client = schwab.auth.client_from_token_file(
            token_path=token_path,
            api_key=app_key,
            app_secret=app_secret,
            asyncio=True  # Enable async support
        )
        print(f"   ✓ Loaded existing token from {args.token_file}")
    else:
        print(f"   Token file '{args.token_file}' not found.")
        print("\n   Starting OAuth authentication flow...")
        print(f"   Callback URL: {args.callback_url}")
        # This will use the patched OAuth endpoints (proxy's OAuth server)
        client = schwab.auth.client_from_login_flow(
            api_key=app_key,
            app_secret=app_secret,
            callback_url=args.callback_url,
            token_path=Path(args.token_file),
            asyncio=True  # Enable async support
        )
        print("   ✓ OAuth flow completed successfully")

    # Get account ID
    print("\n5. Getting account ID...")
    resp = await client.get_account_numbers()
    
    # Handle 401 - try to refresh token once
    if resp.status_code == 401:
        print("   Got 401, attempting to refresh token...")
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
                        print("   Refreshing token...")
                        await client.session.refresh_token(token_endpoint, refresh_token=refresh_token)
                        print("   Token refreshed successfully")
                    else:
                        print("   No refresh token available")
            
            # Retry the request
            resp = await client.get_account_numbers()
        except Exception as e:
            print(f"   Failed to refresh token: {e}")
            
    if resp.status_code == 200:
        accounts = resp.json()
        if accounts:
            account_id = accounts[0]['hashValue']
            print(f"   Account ID: {account_id}")
        else:
            print("   No accounts found")
            return 1
    else:
        print(f"   Failed to get accounts: {resp.status_code}")
        if resp.status_code == 401:
            print("   Authentication failed. Try deleting the token file and re-authenticating.")
        return 1

    # Run streaming test
    await test_streaming(client, account_id, tickers, args.stream_duration)

    print("\n🎉 Streaming test completed!")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Test schwab-proxy streaming functionality",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Stream with existing token file
    python test_streaming.py --app-key YOUR_KEY --app-secret YOUR_SECRET --tickers AAPL,MSFT,GOOGL

    # Stream with custom token file
    python test_streaming.py --app-key YOUR_KEY --app-secret YOUR_SECRET --token-file my_token.json --tickers SPY

    # Fresh authentication with custom callback URL
    python test_streaming.py --app-key YOUR_KEY --app-secret YOUR_SECRET --callback-url https://localhost:9000 --tickers TSLA

    # Use environment variables for credentials
    export SCHWAB_APP_KEY=your_key
    export SCHWAB_APP_SECRET=your_secret
    python test_streaming.py --tickers SPY,QQQ,IWM

    # Test with custom proxy URL and no SSL verification
    python test_streaming.py --proxy-url https://myproxy:8080 --no-verify-ssl --tickers NVDA --stream-duration 60
"""
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
        "--tickers",
        required=True,
        help="Comma-separated list of stock tickers to monitor (e.g., AAPL,MSFT,GOOGL)",
    )
    parser.add_argument(
        "--token-file",
        default="schwab_token.json",
        help="Token file path to save/load OAuth tokens (default: schwab_token.json)",
    )
    parser.add_argument(
        "--callback-url",
        default="https://127.0.0.1:3000",
        help="OAuth callback URL for fresh authentication (default: https://127.0.0.1:3000)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL verification for self-signed certificates",
    )
    parser.add_argument(
        "--stream-duration",
        type=int,
        default=30,
        help="Duration to stream data in seconds (default: 30)",
    )

    args = parser.parse_args()

    # Run async main
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
