"""
Monkeypatch for schwab-py client to redirect API calls to a proxy server.

Usage:
    import schwab_monkeypatch
    schwab_monkeypatch.patch_schwab_client("https://localhost:8080")

    # Now use schwab-py normally and it will use your proxy
    import schwab
    client = schwab.client.Client(...)

IMPORTANT: Call patch_schwab_client() BEFORE importing any schwab modules
to ensure all client references are properly patched.
"""


def patch_schwab_client(proxy_base_url: str, verify_ssl: bool = True):
    """
    Monkeypatch schwab-py client to use a proxy server instead of api.schwabapi.com

    This patches BOTH API endpoints AND OAuth endpoints, since the proxy needs to
    handle authentication to issue valid tokens for API requests.

    Args:
        proxy_base_url: Base URL of your proxy server (e.g., "https://localhost:8080")
        verify_ssl: Whether to verify SSL certificates (default: True, set False for self-signed certs)
    """
    try:
        import schwab.client.synchronous
        import schwab.client.asynchronous

        proxy_base_url = proxy_base_url.rstrip("/")

        _patch_sync_client(schwab.client.synchronous, proxy_base_url)
        _patch_async_client(schwab.client.asynchronous, proxy_base_url)

        import schwab.auth

        _patch_oauth_endpoints(schwab.auth, proxy_base_url, verify_ssl)
        _patch_auth_client_references(
            schwab.auth, schwab.client.synchronous, schwab.client.asynchronous
        )

    except ImportError:
        raise ImportError(
            "schwab-py package not found. Install with: pip install schwab-py"
        )

    print(
        f"schwab-py client patched to use proxy: {proxy_base_url} (verify_ssl={verify_ssl})"
    )


def _patch_sync_client(sync_module, proxy_base_url: str):
    """Patch the synchronous client HTTP methods"""
    Client = sync_module.Client

    def _patched_get_request(self, path, params):
        dest = proxy_base_url + path
        headers = {
            "Authorization": "Bearer " + str(self.token_metadata.token["access_token"])
        }
        # Use the session's internal httpx client which has our SSL settings
        return self.session.session.get(dest, params=params, headers=headers)

    def _patched_post_request(self, path, data):
        dest = proxy_base_url + path
        headers = {
            "Authorization": "Bearer " + str(self.token_metadata.token["access_token"]),
            "Content-Type": "application/json",
        }
        # Use the session's internal httpx client which has our SSL settings
        return self.session.session.post(dest, json=data, headers=headers)

    def _patched_put_request(self, path, data):
        dest = proxy_base_url + path
        headers = {
            "Authorization": "Bearer " + str(self.token_metadata.token["access_token"]),
            "Content-Type": "application/json",
        }
        # Use the session's internal httpx client which has our SSL settings
        return self.session.session.put(dest, json=data, headers=headers)

    def _patched_delete_request(self, path):
        dest = proxy_base_url + path
        headers = {
            "Authorization": "Bearer " + str(self.token_metadata.token["access_token"])
        }
        # Use the session's internal httpx client which has our SSL settings
        return self.session.session.delete(dest, headers=headers)

    # Apply patches
    Client._get_request = _patched_get_request
    Client._post_request = _patched_post_request
    Client._put_request = _patched_put_request
    Client._delete_request = _patched_delete_request


def _patch_async_client(async_module, proxy_base_url: str):
    """Patch the asynchronous client HTTP methods"""
    AsyncClient = async_module.AsyncClient

    async def _patched_async_get_request(self, path, params):
        dest = proxy_base_url + path
        headers = {
            "Authorization": "Bearer " + str(self.token_metadata.token["access_token"])
        }
        # Use the session's internal httpx client which has our SSL settings
        return await self.session.session.get(dest, params=params, headers=headers)

    async def _patched_async_post_request(self, path, data):
        dest = proxy_base_url + path
        headers = {
            "Authorization": "Bearer " + str(self.token_metadata.token["access_token"]),
            "Content-Type": "application/json",
        }
        # Use the session's internal httpx client which has our SSL settings
        return await self.session.session.post(dest, json=data, headers=headers)

    async def _patched_async_put_request(self, path, data):
        dest = proxy_base_url + path
        headers = {
            "Authorization": "Bearer " + str(self.token_metadata.token["access_token"]),
            "Content-Type": "application/json",
        }
        # Use the session's internal httpx client which has our SSL settings
        return await self.session.session.put(dest, json=data, headers=headers)

    async def _patched_async_delete_request(self, path):
        dest = proxy_base_url + path
        headers = {
            "Authorization": "Bearer " + str(self.token_metadata.token["access_token"])
        }
        # Use the session's internal httpx client which has our SSL settings
        return await self.session.session.delete(dest, headers=headers)

    # Apply patches
    AsyncClient._get_request = _patched_async_get_request
    AsyncClient._post_request = _patched_async_post_request
    AsyncClient._put_request = _patched_async_put_request
    AsyncClient._delete_request = _patched_async_delete_request


def _patch_oauth_endpoints(auth_module, proxy_base_url: str, verify_ssl: bool = True):
    """Patch OAuth endpoints in the auth module"""
    # Patch the token endpoint constant
    auth_module.TOKEN_ENDPOINT = f"{proxy_base_url}/v1/oauth/token"

    # Patch the get_auth_context function which creates the authorization URL
    if hasattr(auth_module, "get_auth_context"):

        def make_patched_get_auth_context(ssl_verify):
            def _patched_get_auth_context(api_key, callback_url, state=None):
                # Import OAuth2Client here to avoid import issues
                from authlib.integrations.httpx_client import OAuth2Client
                import httpx

                # Create httpx client with appropriate SSL verification setting
                httpx_client = httpx.Client(verify=ssl_verify)

                # Create OAuth2Client and then override its session
                oauth = OAuth2Client(api_key, redirect_uri=callback_url)
                oauth.session = httpx_client  # Force it to use our custom client
                authorization_url, state = oauth.create_authorization_url(
                    f"{proxy_base_url}/v1/oauth/authorize",  # Use proxy URL instead of Schwab
                    state=state,
                )

                # Import AuthContext from the auth module
                AuthContext = auth_module.collections.namedtuple(
                    "AuthContext", ["callback_url", "authorization_url", "state"]
                )

                return AuthContext(callback_url, authorization_url, state)

            return _patched_get_auth_context

        auth_module.get_auth_context = make_patched_get_auth_context(verify_ssl)

    # Also patch client_from_received_url to use an httpx client with SSL verification setting
    if hasattr(auth_module, "client_from_received_url"):

        def make_patched_client_from_received_url(ssl_verify):
            def _patched_client_from_received_url(
                api_key,
                app_secret,
                auth_context,
                received_url,
                token_write_func,
                asyncio=False,
                enforce_enums=True,
            ):
                from authlib.integrations.httpx_client import OAuth2Client
                import httpx

                # Create httpx client with appropriate SSL verification setting
                httpx_client = httpx.Client(verify=ssl_verify)

                # Create OAuth2Client and then override its session
                oauth = OAuth2Client(api_key, redirect_uri=auth_context.callback_url)
                oauth.session = httpx_client  # Force it to use our custom client

                token = oauth.fetch_token(
                    auth_module.TOKEN_ENDPOINT,  # This now points to our proxy
                    authorization_response=received_url,
                    client_secret=app_secret,
                )

                # Set up token writing and perform the initial token write (like schwab-py does)
                import time

                metadata_manager = auth_module.TokenMetadata(
                    token, int(time.time()), token_write_func
                )
                wrapped_token_write_func = metadata_manager.wrapped_token_write_func()
                wrapped_token_write_func(token)

                # Create httpx client with appropriate SSL verification setting
                import httpx

                httpx_client = httpx.Client(verify=ssl_verify)

                # Create the proper session class (OAuth2Client) as expected by Client constructor
                if asyncio:
                    from authlib.integrations.httpx_client import AsyncOAuth2Client

                    async def oauth_client_update_token(t, *args, **kwargs):
                        wrapped_token_write_func(t, *args, **kwargs)

                    session = AsyncOAuth2Client(
                        api_key,
                        client_secret=app_secret,
                        token=token,
                        update_token=oauth_client_update_token,
                        leeway=300,
                    )
                    session.session = httpx_client  # Set our custom httpx client
                    return auth_module.AsyncClient(
                        api_key,
                        session,
                        token_metadata=metadata_manager,
                        enforce_enums=enforce_enums,
                    )
                else:
                    from authlib.integrations.httpx_client import OAuth2Client

                    session = OAuth2Client(
                        api_key,
                        client_secret=app_secret,
                        token=token,
                        update_token=wrapped_token_write_func,
                        leeway=300,
                    )
                    session.session = httpx_client  # Set our custom httpx client
                    return auth_module.Client(
                        api_key,
                        session,
                        token_metadata=metadata_manager,
                        enforce_enums=enforce_enums,
                    )

            return _patched_client_from_received_url

        auth_module.client_from_received_url = make_patched_client_from_received_url(
            verify_ssl
        )

        # Also patch client_from_access_functions for token file loading
        original_client_from_access_functions = auth_module.client_from_access_functions

        def make_patched_client_from_access_functions(verify_ssl):
            def patched_client_from_access_functions(
                api_key,
                app_secret,
                token_read_func,
                token_write_func,
                asyncio=False,
                enforce_enums=True,
            ):
                # Call original function to get the client
                client = original_client_from_access_functions(
                    api_key,
                    app_secret,
                    token_read_func,
                    token_write_func,
                    asyncio,
                    enforce_enums,
                )

                # Update the session's httpx client to use our SSL verification setting
                import httpx

                httpx_client = httpx.Client(verify=verify_ssl)
                client.session.session = httpx_client

                return client

            return patched_client_from_access_functions

        auth_module.client_from_access_functions = (
            make_patched_client_from_access_functions(verify_ssl)
        )


def _patch_auth_client_references(auth_module, sync_module, async_module):
    """Patch any cached client class references in the auth module"""
    # Update the Client and AsyncClient references in auth module
    # in case they were imported before we patched them
    if hasattr(auth_module, "Client"):
        auth_module.Client = sync_module.Client
    if hasattr(auth_module, "AsyncClient"):
        auth_module.AsyncClient = async_module.AsyncClient


# Convenience function for common use case
def patch_for_localhost(port: int = 8080, https: bool = True, verify_ssl: bool = True):
    """
    Convenience function to patch for localhost proxy

    Args:
        port: Port number (default: 8080)
        https: Use HTTPS (default: True)
        verify_ssl: Whether to verify SSL certificates (default: True)
    """
    protocol = "https" if https else "http"
    patch_schwab_client(f"{protocol}://127.0.0.1:{port}", verify_ssl=verify_ssl)


if __name__ == "__main__":
    # Example usage
    print("Example usage:")
    print("import schwab_monkeypatch")
    print("schwab_monkeypatch.patch_schwab_client('https://127.0.0.1:8080')")
    print("")
    print("# Or for localhost convenience:")
    print("schwab_monkeypatch.patch_for_localhost(8080)")
