from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_repository_root_has_no_loose_files():
    visible = {path.name for path in ROOT.iterdir() if not path.name.startswith(".")}
    assert visible == {
        "README.md",
        "artifacts",
        "config",
        "data",
        "docs",
        "tests",
        "threat2detect",
        "tools",
    }
    assert {path.name for path in ROOT.iterdir() if not path.name.startswith(".") and path.is_file()} == {
        "README.md"
    }


def test_main_modules_live_inside_package():
    expected = {
        "pipeline.py",
        "report_agent.py",
        "contracts.py",
        "sigma/retrieval.py",
        "sigma/coverage.py",
        "sigma/agent.py",
        "sigma/executor.py",
        "telemetry/otrf.py",
    }
    assert {path for path in expected if not (ROOT / "threat2detect" / path).is_file()} == set()
