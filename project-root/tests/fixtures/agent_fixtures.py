import pytest

@pytest.fixture
def agent_fixture():
    # Setup code for agent fixture
    yield
    # Teardown code for agent fixture

@pytest.fixture
def another_agent_fixture():
    # Setup code for another agent fixture
    yield
    # Teardown code for another agent fixture