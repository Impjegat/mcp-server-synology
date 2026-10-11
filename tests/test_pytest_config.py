"""pytest.ini has to be read, or none of its options apply.

It once began with `[tool:pytest]`, the setup.cfg header. In a file named
pytest.ini pytest wants `[pytest]` and silently ignores the file otherwise, so
`--strict-markers`, `testpaths` and the marker list never applied while the
header of every run still said `configfile: pytest.ini`.
"""


def test_pytest_ini_is_parsed(pytestconfig):
    assert pytestconfig.getini("testpaths") == ["tests"]


def test_the_markers_the_tests_use_are_registered_in_pytest_ini(pytestconfig):
    registered = {line.split(":")[0].strip() for line in pytestconfig.getini("markers")}
    assert {"real_nas", "destructive", "slow", "docker"} <= registered
