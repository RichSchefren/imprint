import pytest

from imprint.domains import DomainRegistry, DomainRule, registry_from_config


def registry():
    return DomainRegistry(
        [
            DomainRule("alpha", "Alpha", safe_paths=("Projects/Alpha Work",), keywords=("launch plan",)),
            DomainRule("beta", "Beta", safe_paths=("Projects/Beta Work",), keywords=("retention plan",)),
        ]
    )


def test_precedence_explicit_then_path_then_keyword():
    selected = registry().select(explicit="beta", path="Projects/Alpha Work/file.md", prompt="launch")
    assert (selected.domain_id, selected.method) == ("beta", "explicit")
    selected = registry().select(path="Projects/Alpha Work/file with spaces.md", prompt="retention")
    assert (selected.domain_id, selected.method) == ("alpha", "path")
    selected = registry().select(prompt="retention plan")
    assert (selected.domain_id, selected.method) == ("beta", "keyword")


def test_ties_never_guess_and_invalid_explicit_does_not_fall_through():
    tied = DomainRegistry(
        [DomainRule("alpha", "Alpha", keywords=("shared",)), DomainRule("beta", "Beta", keywords=("shared",))]
    )
    result = tied.select(prompt="shared")
    assert result.domain_id is None
    assert result.diagnostic_code == "domain_keyword_tie"
    invalid = registry().select(explicit="../../private", path="Projects/Alpha Work")
    assert invalid.domain_id is None
    assert invalid.diagnostic_code == "domain_explicit_invalid"


def test_path_tie_and_traversal_return_no_domain():
    tied = DomainRegistry(
        [DomainRule("alpha", "Alpha", safe_paths=("Projects/Common",)), DomainRule("beta", "Beta", safe_paths=("Projects/Common",))]
    )
    assert tied.select(path="Projects/Common/a.md").diagnostic_code == "domain_path_tie"
    assert registry().select(path="Projects/../Alpha Work/a.md").domain_id is None


def test_registry_rejects_unsafe_and_duplicate_ids():
    with pytest.raises(ValueError, match="unsafe"):
        DomainRule("Bad ID", "Bad")
    with pytest.raises(ValueError, match="duplicate"):
        DomainRegistry([DomainRule("same", "One"), DomainRule("same", "Two")])


def test_registry_loads_closed_config_and_selects_in_priority_order():
    loaded = registry_from_config({"domains": [{
        "domain_id": "research", "public_label": "Research",
        "safe_paths": ["projects/research"], "keywords": ["sources", "evidence"],
        "frozen": True,
    }]})
    assert loaded.select(explicit="research").domain_id == "research"
    assert loaded.select(path="projects/research/report.md").method == "path"
    assert loaded.select(prompt="check the evidence sources").method == "keyword"


@pytest.mark.parametrize("domains", [
    {},
    [{"domain_id": "x", "public_label": "X", "surprise": True}],
    [{"domain_id": "x", "public_label": "X", "safe_paths": "not-a-list"}],
])
def test_registry_config_fails_closed(domains):
    with pytest.raises(ValueError):
        registry_from_config({"domains": domains})
