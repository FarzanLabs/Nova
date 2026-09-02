from nova.modules.tls import flatten_name


def test_flatten_name():
    value = [[("commonName", "example.com")]]

    assert flatten_name(value) == "commonName=example.com"


def test_empty_name():
    assert flatten_name([]) is None
