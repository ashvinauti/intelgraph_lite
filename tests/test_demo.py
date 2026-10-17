import subprocess
import sys
from pathlib import Path

import pytest

from iglite import attack, demo
from iglite.cli import main
from iglite.extract import treat_as_public

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def demo_run(tmp_path):
    engine, watch, network = demo.build(str(tmp_path / "demo.db"))
    try:
        yield engine, watch, network
    finally:
        engine.store.close()
        treat_as_public([])


def test_the_scripted_incidents_are_caught_and_the_trap_is_not(demo_run):
    engine, watch, network = demo_run
    assert engine.demo and "simulated home network (demo)" in watch.gateway.status()["inputs"]
    for ip, name in demo.DEVICES.items():
        network.gw.add(demo.Lease(ip, name))
    network.incidents(60)
    for _ in range(4):
        network.background()
    watch.scan()

    alerted = {a["key"]: a["verdict"] for a in engine.store.alerts()}
    assert alerted == {
        f"ip:{demo.C2_IP}": "malicious",
        f"domain:{demo.PHISH}": "malicious",
        f"domain:{demo.MINER}": "malicious",
        f"domain:{demo.DROPPER}": "malicious",
    }
    rows = {r["remote_ip"]: r for r in watch.rows}
    assert rows[demo.SCANNER]["verdict"] == "suspicious"  # one feed, low confidence: no alert
    assert rows[demo.CDN_IP]["verdict"] not in ("malicious", "suspicious")  # stale entry outweighed

    devices = {d["name"]: d for d in watch.devices()}
    assert devices["Smart-Plug"]["worst"] == "malicious" and devices["Family-NAS"]["worst"] == "suspicious"
    assert len(devices) >= 7

    techs = {
        t["id"]: t["basis"] for tac in attack.summary(engine.store)["tactics"] for t in tac["techniques"]
    }
    for tid in ("T1571", "T1566.002", "T1496", "T1105"):
        assert tid in techs, tid
    assert "observed" in techs["T1071"]  # from the IDS signature


def test_demo_never_touches_the_users_database(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: calls.append(cfg))
    monkeypatch.setattr(demo, "run", lambda *a, **k: calls.append((a, k)))
    assert main(["demo", "--no-browser", "--port", "9999", "--speed", "2"]) == 0
    assert calls == [(("127.0.0.1", 9999), {"open_browser": False, "speed": 2.0, "db": None})]


def test_single_file_build_runs(tmp_path):
    out = tmp_path / "iglite.pyz"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build-pyz.py"), "-o", str(out)], check=True)
    run = subprocess.run(
        [sys.executable, str(out), "--db", str(tmp_path / "x.db"), "attack", "T1566.002"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert run.returncode == 0, run.stderr
    assert "Spearphishing Link" in run.stdout  # the catalogue loads from inside the zip
