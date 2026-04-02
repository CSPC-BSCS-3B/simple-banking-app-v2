import os

import pytest
import requests


@pytest.fixture
def base_url():
    """Provide a base URL for integration tests.

    Set BASE_URL to target a running instance (local, staging, or production).
    Defaults to local Flask dev server.
    """
    url = os.environ.get("BASE_URL", "http://127.0.0.1:5000")

    try:
        requests.get(f"{url}/login", timeout=3)
    except requests.RequestException:
        pytest.skip(
            "Integration target is not reachable. "
            "Start the app or set BASE_URL to a reachable deployment."
        )

    return url
