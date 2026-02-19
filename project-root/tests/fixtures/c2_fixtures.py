import pytest

@pytest.fixture(scope='module')
def c2_setup():
    # Setup logic for C2 framework
    yield
    # Teardown logic for C2 framework

@pytest.fixture(scope='module')
def c2_specific_fixture():
    # Setup logic for a specific C2 test
    yield
    # Teardown logic for a specific C2 test

@pytest.fixture(scope='function')
def c2_functional_fixture():
    # Setup logic for C2 functional tests
    yield
    # Teardown logic for C2 functional tests