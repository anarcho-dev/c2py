import pytest
from tests.fixtures.c2_fixtures import c2_fixture
from tests.fixtures.polymorphic_fixtures import polymorphic_fixture
from tests.fixtures.agent_fixtures import agent_fixture

def test_c2_fixture(c2_fixture):
    assert c2_fixture is not None

def test_polymorphic_fixture(polymorphic_fixture):
    assert polymorphic_fixture is not None

def test_agent_fixture(agent_fixture):
    assert agent_fixture is not None