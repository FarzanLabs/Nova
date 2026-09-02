from nova.modules.correlation import InvestigationGraph


def test_graph_deduplicates_relationships():
    graph = InvestigationGraph(target="example.com")

    graph.add(
        "example.com",
        "resolves_to",
        "1.2.3.4",
        "domain",
        "ip",
    )

    graph.add(
        "example.com",
        "resolves_to",
        "1.2.3.4",
        "domain",
        "ip",
    )

    assert len(graph.relationships) == 1
    assert "example.com" in graph.nodes()
    assert "1.2.3.4" in graph.nodes()


def test_graph_to_dict():
    graph = InvestigationGraph(target="example.com")

    graph.add(
        "example.com",
        "resolves_to",
        "1.2.3.4",
        "domain",
        "ip",
    )

    data = graph.to_dict()

    assert data["target"] == "example.com"
    assert len(data["relationships"]) == 1

