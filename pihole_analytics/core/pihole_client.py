"""
Pi-hole API client.

This module provides a robust client for interacting with Pi-hole's API,
including authentication, query fetching, and error handling.
"""

import time
from typing import Dict, List, Optional, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..utils.config import PiholeConfig
from ..utils.logging import LoggerMixin
from ..utils.models import DNSQuery


class PiholeAPIError(Exception):
    """Custom exception for Pi-hole API errors."""


class PiholeAuthError(PiholeAPIError):
    """Authentication error with Pi-hole."""


class PiholeClient(LoggerMixin):
    """Client for interacting with Pi-hole API."""

    def __init__(self, config: PiholeConfig):
        """Initialize Pi-hole client with configuration."""
        self.config = config
        self._session_id: Optional[str] = None
        self._session = self._create_session()
        self._version_info: Optional[Dict[str, Any]] = None

        self.logger.info("Initialized Pi-hole client for host: %s:%d",
                         config.host, config.port)

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry configuration."""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "DELETE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _api_url(self, path: str) -> str:
        """Construct full Pi-hole API URL from path."""
        if path.startswith("/"):
            path = path[1:]
        return f"{self.config.base_url}/api/{path}"

    def get_version(self) -> Dict[str, Any]:
        """
        Get Pi-hole version information.

        Returns:
            Dictionary containing version information

        Raises:
            PiholeAPIError: If fetching version fails
        """
        if self._version_info:
            return self._version_info

        self.log_method_call("get_version")

        # Version endpoint typically doesn't require authentication
        url = self._api_url("version")

        try:
            response = self._session.get(url, timeout=self.config.timeout)
            response.raise_for_status()

            data = response.json()
            self._version_info = data
            version_str = data.get("version", "unknown")
            self.logger.info("Pi-hole version detected: %s", version_str)
            return data

        except requests.RequestException as error:
            self.logger.warning("Failed to fetch version: %s", error)
            # Return empty dict if version detection fails
            self._version_info = {}
            return self._version_info

    def _is_v6_or_later(self) -> bool:
        """Check if Pi-hole is version 6.0 or later."""
        if not self._version_info:
            self.get_version()

        if self._version_info:
            version_str = self._version_info.get("version", "")
            if version_str and version_str.startswith(("v6.", "6.", "v7.", "7.")):
                return True
        return False

    def authenticate(self, retries: int = 3, backoff: float = 0.5) -> str:
        """
        Authenticate to Pi-hole and return session ID.

        Args:
            retries: Number of retry attempts
            backoff: Backoff factor for retries

        Returns:
            Session ID string

        Raises:
            PiholeAuthError: If authentication fails
        """
        self.log_method_call("authenticate", retries=retries)

        url = self._api_url("auth")
        payload = {"password": self.config.password}
        headers = {"Content-Type": "application/json"}

        for attempt in range(1, retries + 1):
            try:
                response = self._session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.config.timeout
                )
                response.raise_for_status()

                data = response.json()
                session_info = data.get("session", {})
                sid = session_info.get("sid")
                valid = session_info.get("valid", False)

                if valid and sid:
                    self._session_id = sid
                    self.logger.info("Successfully authenticated to Pi-hole")
                    return sid

                message = session_info.get("message", "unknown")
                raise PiholeAuthError(f"Authentication failed: {message}")

            except (requests.RequestException, PiholeAuthError, KeyError, ValueError) as error:
                self.logger.warning(
                    "Authentication attempt %d failed: %s", attempt, error)
                if attempt == retries:
                    raise PiholeAuthError(
                        f"Authentication failed after {retries} attempts: {error}") from error
                time.sleep(backoff * attempt)

        raise PiholeAuthError("Authentication failed: unexpected error")

    def fetch_queries(self, count: int = 100) -> List[DNSQuery]:
        """
        Fetch DNS queries from Pi-hole.

        Args:
            count: Maximum number of queries to fetch

        Returns:
            List of DNSQuery objects

        Raises:
            PiholeAPIError: If fetching queries fails
        """
        self.log_method_call("fetch_queries", count=count)

        # Try multiple authentication methods for Pi-hole v6+ compatibility
        auth_methods = [
            # Method 1: Session ID (works for most endpoints)
            lambda: self._fetch_queries_with_session(count),
            # Method 2: Password-based authentication (for queries endpoint)
            lambda: self._fetch_queries_with_password(count),
            # Method 3: Legacy API token method
            lambda: self._fetch_queries_with_token(count)
        ]

        last_error = None
        for i, auth_method in enumerate(auth_methods, 1):
            try:
                self.logger.info(
                    "Trying authentication method %d for queries", i)
                return auth_method()
            except (PiholeAPIError, requests.RequestException) as error:
                self.logger.warning(
                    "Authentication method %d failed: %s", i, error)
                last_error = error
                continue

        # If all methods fail, provide helpful error message and potential workaround
        self.logger.error(
            "All authentication methods failed for queries endpoint")
        self.logger.info(
            "This may be due to Pi-hole v6+ security restrictions")
        self.logger.info(
            "Consider checking Pi-hole settings or using summary data instead")

        # For now, return an empty list to allow the application to continue
        # This prevents the application from crashing due to Pi-hole API restrictions
        self.logger.warning(
            "Returning empty query list due to API restrictions")
        return []

    def _fetch_queries_with_session(self, count: int) -> List[DNSQuery]:
        """Fetch queries using session-based authentication."""
        if not self._session_id:
            self.authenticate()

        url = self._api_url(f"queries?sid={self._session_id}")
        return self._execute_queries_request(url, count, "session-based")

    def _fetch_queries_with_password(self, count: int) -> List[DNSQuery]:
        """Fetch queries using password-based authentication."""
        # Try multiple password-based approaches for different Pi-hole versions
        methods = [
            # Method 1: Pi-hole v6+ API format with POST
            ("history", "POST", {
             "auth": self.config.password, "from": 0, "until": count}),
            # Method 2: Password in URL parameter (v5.x format)
            (f"queries?auth={self.config.password}", "GET"),
            # Method 3: POST with password in body (v5.x alternative)
            ("queries", "POST", {"auth": self.config.password}),
            # Method 4: Legacy admin API format
            (f"../admin/api.php?allQueries&auth={self.config.password}", "GET"),
            # Method 5: Pi-hole v6+ alternative path
            (f"queries/recent?auth={self.config.password}", "GET"),
        ]

        for method_data in methods:
            endpoint = method_data[0]
            http_method = method_data[1]
            payload = method_data[2] if len(method_data) > 2 else None

            try:
                url = self._api_url(endpoint)
                self.logger.debug("Trying %s %s", http_method, url)

                if http_method == "POST" and payload:
                    response = self._session.post(
                        url,
                        json=payload,
                        timeout=self.config.timeout
                    )
                else:
                    response = self._session.get(
                        url, timeout=self.config.timeout)

                response.raise_for_status()
                self.logger.info(
                    "Successfully connected using %s method", endpoint)
                return self._parse_queries_response(response, count, f"password-{http_method}-{endpoint}")

            except requests.RequestException as e:
                self.logger.debug("Method %s failed: %s", endpoint, e)
                continue  # Try next method

        raise PiholeAPIError(
            "All password-based authentication methods failed")

    def _fetch_queries_with_token(self, count: int) -> List[DNSQuery]:
        """Fetch queries using legacy token-based authentication."""
        # Some Pi-hole installations might still use API tokens
        url = self._api_url(f"queries?auth={self.config.password}")
        return self._execute_queries_request(url, count, "token-based")

    def _execute_queries_request(self, url: str, count: int, method: str) -> List[DNSQuery]:
        """Execute a GET request for queries."""
        try:
            response = self._session.get(url, timeout=self.config.timeout)
            response.raise_for_status()
            return self._parse_queries_response(response, count, method)
        except requests.RequestException as error:
            raise PiholeAPIError(f"{method} query failed: {error}") from error

    def _parse_queries_response(self, response: requests.Response, count: int, method: str) -> List[DNSQuery]:
        """Parse the queries response and convert to DNSQuery objects."""
        try:
            data = response.json()

            # Handle different response formats from various Pi-hole versions
            raw_queries = []

            # Pi-hole v6+ history format: {"history": [...]}
            if "history" in data and isinstance(data["history"], list):
                raw_queries = data["history"]
            # Standard API format: {"queries": [...]}
            elif "queries" in data and isinstance(data["queries"], list):
                raw_queries = data["queries"]
            # Legacy API format: {"data": [...]}
            elif "data" in data and isinstance(data["data"], list):
                raw_queries = data["data"]
            # Direct array format: [...]
            elif isinstance(data, list):
                raw_queries = data
            # Pi-hole v6+ might use "results" key
            elif "results" in data and isinstance(data["results"], list):
                raw_queries = data["results"]
            else:
                self.logger.warning("Unexpected response structure from %s: %s",
                                    method, list(data.keys()) if isinstance(data, dict) else type(data).__name__)
                # Log a sample of the response for debugging
                if isinstance(data, dict) and data:
                    sample_key = list(data.keys())[0]
                    self.logger.debug("Sample response content: %s: %s",
                                      sample_key, str(data[sample_key])[:200])
                return []

            self.logger.info(
                "Fetched %d queries from Pi-hole using %s", len(raw_queries), method)

            # Convert to DNSQuery objects and limit count
            queries = []
            for query_data in raw_queries[:count]:
                try:
                    query = DNSQuery.from_pihole_data(query_data)
                    queries.append(query)
                except (ValueError, KeyError, TypeError) as error:
                    self.logger.warning(
                        "Failed to parse query data: %s", error)
                    # Log the problematic data for debugging
                    self.logger.debug("Problematic query data: %s", query_data)
                    continue

            self.logger.info(
                "Successfully parsed %d queries", len(queries))
            return queries

        except (ValueError, KeyError) as error:
            self.logger.error(
                "Failed to parse JSON response from %s: %s", method, error)
            # Log response content for debugging
            self.logger.debug("Response content: %s", response.text[:500])
            raise PiholeAPIError(
                f"Failed to parse query response: {error}") from error

    def get_summary(self) -> Dict[str, Any]:
        """
        Get Pi-hole summary statistics.

        Returns:
            Dictionary containing summary statistics

        Raises:
            PiholeAPIError: If fetching summary fails
        """
        if not self._session_id:
            self.authenticate()

        self.log_method_call("get_summary")

        # Try multiple endpoints for summary data
        endpoints = [
            f"summary?sid={self._session_id}",
            f"stats?sid={self._session_id}",
            f"status?sid={self._session_id}",
        ]

        for endpoint in endpoints:
            try:
                url = self._api_url(endpoint)
                response = self._session.get(url, timeout=self.config.timeout)

                if response.status_code == 404:
                    continue  # Try next endpoint

                response.raise_for_status()
                data = response.json()
                self.logger.info(
                    "Successfully fetched Pi-hole summary from %s", endpoint)
                return data

            except requests.RequestException as error:
                self.logger.debug(
                    "Summary endpoint %s failed: %s", endpoint, error)
                continue

        # If all endpoints fail, return minimal summary
        self.logger.warning(
            "All summary endpoints failed, returning minimal data")
        return {
            "status": "unknown",
            "queries_all_types": 0,
            "blocked_queries": 0,
            "note": "Unable to fetch summary from Pi-hole API - endpoints may be restricted"
        }

    def get_top_domains(self, count: int = 10) -> Dict[str, Any]:
        """
        Get top queried domains.

        Args:
            count: Number of top domains to fetch

        Returns:
            Dictionary containing top domains data

        Raises:
            PiholeAPIError: If fetching top domains fails
        """
        if not self._session_id:
            self.authenticate()

        self.log_method_call("get_top_domains", count=count)

        url = self._api_url(f"topItems?sid={self._session_id}")

        try:
            response = self._session.get(url, timeout=self.config.timeout)
            response.raise_for_status()

            data = response.json()
            self.logger.info("Successfully fetched top domains")
            return data

        except requests.RequestException as error:
            self.log_error(error, {"operation": "get_top_domains"})
            raise PiholeAPIError(
                f"Failed to fetch top domains: {error}") from error

    def get_top_clients(self) -> Dict[str, Any]:
        """
        Get top client devices.

        Returns:
            Dictionary containing top clients data

        Raises:
            PiholeAPIError: If fetching top clients fails
        """
        if not self._session_id:
            self.authenticate()

        self.log_method_call("get_top_clients")

        url = self._api_url(f"topClients?sid={self._session_id}")

        try:
            response = self._session.get(url, timeout=self.config.timeout)
            response.raise_for_status()

            data = response.json()
            self.logger.info("Successfully fetched top clients")
            return data

        except requests.RequestException as error:
            self.log_error(error, {"operation": "get_top_clients"})
            raise PiholeAPIError(
                f"Failed to fetch top clients: {error}") from error

    def logout(self) -> None:
        """Log out of Pi-hole session."""
        if not self._session_id:
            return

        self.log_method_call("logout")

        url = self._api_url(f"auth?sid={self._session_id}")

        try:
            self._session.delete(url, timeout=5)
            self.logger.info("Successfully logged out of Pi-hole")
        except requests.RequestException as error:
            self.logger.warning("Failed to logout gracefully: %s", error)
        finally:
            self._session_id = None

    def __enter__(self) -> 'PiholeClient':
        """Context manager entry."""
        self.authenticate()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.logout()
