from nova.modules.enrichment import GeoSource, choose_consensus


def test_geo_consensus():
    sources = [
        GeoSource(
            source="one",
            country="Canada",
            country_code="CA",
        ),
        GeoSource(
            source="two",
            country="Canada",
            country_code="CA",
        ),
        GeoSource(
            source="three",
            country="Oman",
            country_code="OM",
        ),
    ]

    country, confidence = choose_consensus(sources)

    assert country == "CA"
    assert confidence == "Medium"


def test_single_provider_is_low_confidence():
    sources = [
        GeoSource(
            source="one",
            country="Canada",
            country_code="CA",
        )
    ]

    country, confidence = choose_consensus(sources)

    assert country == "CA"
    assert confidence == "Low"


def test_unavailable_country_returns_unknown():
    sources = [
        GeoSource(source="one"),
        GeoSource(source="two"),
    ]

    country, confidence = choose_consensus(sources)

    assert country is None
    assert confidence == "Unknown"

