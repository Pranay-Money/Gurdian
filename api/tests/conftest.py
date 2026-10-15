"""
Pytest configuration for API tests
"""
import locale
import sys
from pathlib import Path

# Force UTF-8 on Windows so fixtures with Hindi text decode correctly.
locale.getpreferredencoding = lambda do_setlocale=True: "UTF-8"

# Add the project root to path so imports like `src...` resolve correctly.
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    import asyncio
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow tests")