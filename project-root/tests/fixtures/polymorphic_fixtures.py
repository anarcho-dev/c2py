import pytest

@pytest.fixture(scope='module')
def polymorphic_context():
    # Setup code for polymorphic obfuscation engines
    context = {}
    # Initialize context
    yield context
    # Teardown code
    context.clear()

@pytest.fixture
def polymorphic_obfuscation(polymorphic_context):
    # Setup for specific obfuscation tests
    obfuscation_instance = create_obfuscation_instance(polymorphic_context)
    yield obfuscation_instance
    # Teardown code
    obfuscation_instance.cleanup()