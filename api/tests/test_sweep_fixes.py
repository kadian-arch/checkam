"""Found by an outside tester on the live site: an unauthenticated analyst call, a chatty public health page, soft 404s."""
import pytest
from fastapi.testclient import TestClient

from checkam import config
from checkam.app import app

client = TestClient(app)
WEB = config.ROOT / "web" / "dist"


def test_a_dossier_needs_a_signed_in_analyst():
    r = client.post("/run", json={"mode": "investigate"})
    assert r.status_code == 401


def test_the_public_health_page_says_only_that_it_is_alive():
    assert client.get("/health").json() == {"ok": True}


@pytest.mark.skipif(not (WEB / "index.html").exists(), reason="web app not built here")
def test_a_missing_file_is_a_404_but_app_routes_still_load():
    assert client.get("/nope.php").status_code == 404
    assert client.get("/v/C-00000000").status_code == 200
    assert client.get("/").status_code == 200


@pytest.mark.skipif(not (WEB / "robots.txt").exists(), reason="web app not built here")
def test_robots_exists_and_the_privacy_route_loads_the_app():
    assert client.get("/robots.txt").status_code == 200
    assert client.get("/privacy").status_code == 200
