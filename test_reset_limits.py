"""Tests for the rate-limit reset (juniper_tide) support.

Layer 1: api_usage_fetcher — at_wall usage GET, juniper_tide status mapping,
reset_rate_limits claim POST. All offline — HTTP is monkeypatched via
api_usage_fetcher._urlopen (same convention as test_api_usage_fetcher.py).
"""
import json
import urllib.error

import pytest

import api_usage_fetcher as auf


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# ---- _http_get_usage at_wall variant ----

def test_get_usage_at_wall_appends_query(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured['url'] = req.full_url
        return FakeResponse({'five_hour': None})

    monkeypatch.setattr(auf, '_urlopen', fake_urlopen)
    auf._http_get_usage('TOK', at_wall=True)
    assert captured['url'] == auf.USAGE_URL + '?at_wall=1&skip_spend=1'


def test_get_usage_default_url_unchanged(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured['url'] = req.full_url
        return FakeResponse({'five_hour': None})

    monkeypatch.setattr(auf, '_urlopen', fake_urlopen)
    auf._http_get_usage('TOK')
    assert captured['url'] == auf.USAGE_URL


# ---- map_reset_status ----

def test_map_reset_status_available():
    api = {'juniper_tide': {
        'eligible': True, 'ineligible_reason': None, 'available': True,
        'next_available_at': None}}
    st = auf.map_reset_status(api)
    assert st == {'eligible': True, 'available': True,
                  'next_available_at': None, 'ineligible_reason': None}


def test_map_reset_status_unavailable_with_next():
    api = {'juniper_tide': {
        'eligible': True, 'available': False,
        'next_available_at': '2026-11-22T10:00:00Z'}}
    st = auf.map_reset_status(api)
    assert st['available'] is False
    assert st['next_available_at'] == '2026-11-22T10:00:00Z'


def test_map_reset_status_absent_field_returns_none():
    assert auf.map_reset_status({'five_hour': {}}) is None


def test_map_reset_status_malformed_returns_none():
    # Experimental API: a non-object or fieldless block must degrade to None,
    # never raise into the collector.
    assert auf.map_reset_status({'juniper_tide': 'nope'}) is None
    assert auf.map_reset_status({'juniper_tide': None}) is None


# ---- claim_rate_limit_reset ----

def test_claim_posts_program_with_oauth_headers(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured['url'] = req.full_url
        captured['method'] = req.get_method()
        captured['body'] = json.loads(req.data.decode())
        captured['auth'] = req.get_header('Authorization')
        captured['beta'] = req.get_header('Anthropic-beta')
        captured['ua'] = req.get_header('User-agent')
        return FakeResponse({'result': 'ok',
                             'next_available_at': '2026-11-27T10:00:00Z'})

    monkeypatch.setattr(auf, '_urlopen', fake_urlopen)
    out = auf.claim_rate_limit_reset('TOK', 'org-uuid-1')
    assert out == {'result': 'ok', 'next_available_at': '2026-11-27T10:00:00Z'}
    assert captured['url'] == \
        'https://api.anthropic.com/api/organizations/org-uuid-1/reset_rate_limits'
    assert captured['method'] == 'POST'
    assert captured['body'] == {'program': 'juniper_tide'}
    assert captured['auth'] == 'Bearer TOK'
    assert captured['beta'] == 'oauth-2025-04-20'
    assert captured['ua'].startswith('claude-code/')


def test_claim_maps_http_error_status(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.HTTPError('u', 429, 'Too Many', {}, None)

    monkeypatch.setattr(auf, '_urlopen', boom)
    with pytest.raises(auf.UsageApiError) as ei:
        auf.claim_rate_limit_reset('TOK', 'org-uuid-1')
    assert ei.value.status == 429


def test_claim_requires_org_uuid():
    with pytest.raises(auf.UsageApiError):
        auf.claim_rate_limit_reset('TOK', '')


# ---- Layer 2: accounts.organization_uuid persistence ----

import config          # noqa: E402
import crypto_util     # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402
from database import UsageDatabase      # noqa: E402

FAR = 9_999_999_999_999


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, 'TOKEN_ENCRYPTION_KEY', Fernet.generate_key().decode())
    crypto_util._reset_cache()
    d = UsageDatabase(str(tmp_path / 'r.db'))
    yield d
    d.close()


def _add(db, email='a@x.com', org_uuid=None):
    return db.add_or_update_account(
        label=email, email=email, account_type='max',
        access_token='AT', refresh_token='RT', expires_at=FAR,
        organization_uuid=org_uuid)


def test_account_stores_organization_uuid(db):
    a = _add(db, org_uuid='org-1')
    assert db.get_account_for_primer(a)['organization_uuid'] == 'org-1'


def test_account_org_uuid_defaults_to_none(db):
    a = _add(db)
    assert db.get_account_for_primer(a)['organization_uuid'] is None


def test_reauth_without_org_uuid_keeps_existing(db):
    a = _add(db, org_uuid='org-1')
    a2 = _add(db, org_uuid=None)           # upsert by same email, no uuid known
    assert a2 == a
    assert db.get_account_for_primer(a)['organization_uuid'] == 'org-1'


def test_reauth_with_org_uuid_updates(db):
    a = _add(db, org_uuid='org-1')
    _add(db, org_uuid='org-2')
    assert db.get_account_for_primer(a)['organization_uuid'] == 'org-2'


def test_set_account_org_uuid_backfills(db):
    a = _add(db)
    db.set_account_org_uuid(a, 'org-9')
    assert db.get_account_for_primer(a)['organization_uuid'] == 'org-9'


# ---- Layer 3: oauth_flow.fetch_profile exposes the organization uuid ----

import oauth_flow  # noqa: E402


def test_fetch_profile_returns_organization_uuid(monkeypatch):
    monkeypatch.setattr(oauth_flow, '_urlopen',
                        lambda req, timeout=None: FakeResponse({
                            'account': {'email': 'a@x.com', 'has_claude_max': True},
                            'organization': {'uuid': 'org-uuid-7',
                                             'organization_type': 'claude_max'}}))
    p = oauth_flow.fetch_profile('TOK')
    assert p['organization_uuid'] == 'org-uuid-7'
    assert p['email'] == 'a@x.com'


def test_fetch_profile_org_uuid_none_when_absent(monkeypatch):
    monkeypatch.setattr(oauth_flow, '_urlopen',
                        lambda req, timeout=None: FakeResponse({
                            'account': {'email': 'a@x.com'}}))
    assert oauth_flow.fetch_profile('TOK')['organization_uuid'] is None


# ---- Layer 4: resetter orchestration (mirrors test_primer.py style) ----

import resetter  # noqa: E402

FUTURE = "2999-01-01T00:00:00+00:00"


def _usage(juniper=None):
    """A minimal usage response; juniper injects the juniper_tide block."""
    api = {
        "five_hour": {"utilization": 99.0, "resets_at": FUTURE},
        "seven_day": {"utilization": 10.0, "resets_at": FUTURE},
    }
    if juniper is not None:
        api['juniper_tide'] = juniper
    return api


AVAILABLE = {'eligible': True, 'available': True, 'next_available_at': None}
UNAVAILABLE = {'eligible': True, 'available': False,
               'next_available_at': '2026-11-22T10:00:00Z'}


def test_get_reset_status_reads_at_wall(db, monkeypatch):
    a = _add(db, org_uuid='org-1')
    account = db.get_account_for_primer(a)
    captured = {}

    def usage(token, at_wall=False):
        captured['at_wall'] = at_wall
        return _usage(AVAILABLE)

    monkeypatch.setattr(resetter.auf, '_http_get_usage', usage)
    st = resetter.get_reset_status(db, account)
    assert captured['at_wall'] is True
    assert st['available'] is True


def test_reset_claims_when_available(db, monkeypatch):
    a = _add(db, org_uuid='org-1')
    account = db.get_account_for_primer(a)
    claimed = {}

    monkeypatch.setattr(resetter.auf, '_http_get_usage',
                        lambda token, at_wall=False: _usage(AVAILABLE))

    def claim(token, org_uuid):
        claimed['org'] = org_uuid
        return {'result': 'reset', 'next_available_at': '2026-11-27T10:00:00Z'}

    monkeypatch.setattr(resetter.auf, 'claim_rate_limit_reset', claim)
    out = resetter.reset_account(db, account)
    assert out['reset'] is True
    assert out['result'] == 'reset'
    assert out['next_available_at'] == '2026-11-27T10:00:00Z'
    assert claimed['org'] == 'org-1'
    assert db.get_current(account_id=a) is not None   # post-claim snapshot


def test_reset_blocked_when_unavailable(db, monkeypatch):
    a = _add(db, org_uuid='org-1')
    account = db.get_account_for_primer(a)
    claims = {'n': 0}

    monkeypatch.setattr(resetter.auf, '_http_get_usage',
                        lambda token, at_wall=False: _usage(UNAVAILABLE))
    monkeypatch.setattr(resetter.auf, 'claim_rate_limit_reset',
                        lambda token, org: claims.__setitem__('n', claims['n'] + 1))

    out = resetter.reset_account(db, account)
    assert out['reset'] is False
    assert out['result'] == 'unavailable'
    assert out['next_available_at'] == '2026-11-22T10:00:00Z'
    assert claims['n'] == 0                 # never claims when not available


def test_reset_claims_when_status_unknown(db, monkeypatch):
    # Live finding (2026-11-20): Team accounts answer juniper_tide=null on the
    # OAuth surface even at the wall. Unknown status must NOT block the claim —
    # the server is the real gate (an ineligible claim returns a result and
    # consumes nothing). Only a KNOWN-unavailable status blocks client-side.
    a = _add(db, org_uuid='org-1')
    account = db.get_account_for_primer(a)

    monkeypatch.setattr(resetter.auf, '_http_get_usage',
                        lambda token, at_wall=False: _usage())
    monkeypatch.setattr(resetter.auf, 'claim_rate_limit_reset',
                        lambda token, org: {'result': 'ineligible',
                                            'next_available_at': None})
    out = resetter.reset_account(db, account)
    assert out['reset'] is False
    assert out['result'] == 'ineligible'    # the server's verdict, passed through


def test_reset_backfills_org_uuid_from_profile(db, monkeypatch):
    a = _add(db)                             # no org uuid stored
    account = db.get_account_for_primer(a)
    claimed = {}

    monkeypatch.setattr(resetter.auf, '_http_get_usage',
                        lambda token, at_wall=False: _usage(AVAILABLE))
    monkeypatch.setattr(resetter.oauth_flow, 'fetch_profile',
                        lambda token: {'email': 'a@x.com', 'account_type': 'max',
                                       'organization_uuid': 'org-lazy'})
    monkeypatch.setattr(resetter.auf, 'claim_rate_limit_reset',
                        lambda token, org: claimed.update(org=org) or
                        {'result': 'reset', 'next_available_at': None})

    out = resetter.reset_account(db, account)
    assert out['reset'] is True
    assert claimed['org'] == 'org-lazy'
    # persisted for next time — no profile fetch needed again
    assert db.get_account_for_primer(a)['organization_uuid'] == 'org-lazy'


def test_reset_passes_through_non_reset_result(db, monkeypatch):
    a = _add(db, org_uuid='org-1')
    account = db.get_account_for_primer(a)

    monkeypatch.setattr(resetter.auf, '_http_get_usage',
                        lambda token, at_wall=False: _usage(AVAILABLE))
    monkeypatch.setattr(resetter.auf, 'claim_rate_limit_reset',
                        lambda token, org: {'result': 'not_limited',
                                            'next_available_at': None})
    out = resetter.reset_account(db, account)
    assert out['reset'] is False
    assert out['result'] == 'not_limited'


def test_reset_success_survives_postclaim_read_failure(db, monkeypatch):
    a = _add(db, org_uuid='org-1')
    account = db.get_account_for_primer(a)
    reads = {'n': 0}

    def usage(token, at_wall=False):
        reads['n'] += 1
        if reads['n'] == 1:
            return _usage(AVAILABLE)
        raise resetter.auf.UsageApiError('post-claim read boom')

    monkeypatch.setattr(resetter.auf, '_http_get_usage', usage)
    monkeypatch.setattr(resetter.auf, 'claim_rate_limit_reset',
                        lambda token, org: {'result': 'reset',
                                            'next_available_at': None})
    out = resetter.reset_account(db, account)
    assert out['reset'] is True             # claim succeeded; read failure is best-effort


# ---- Layer 5: routes (mirrors test_start_session_route.py style) ----

import os  # noqa: E402

os.environ.setdefault('ALLOW_DEFAULT_CREDENTIALS', '1')

import app as app_module  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, 'TOKEN_ENCRYPTION_KEY', Fernet.generate_key().decode())
    crypto_util._reset_cache()
    d = UsageDatabase(str(tmp_path / 'route.db'))
    monkeypatch.setattr(app_module, '_db', d)
    app_module.app.config.update(TESTING=True)
    c = app_module.app.test_client()
    with c.session_transaction() as sess:
        sess['logged_in'] = True
    yield c
    d.close()


def test_reset_limit_route_success(client, monkeypatch):
    a = _add(app_module._db, org_uuid='org-1')
    monkeypatch.setattr(resetter, 'reset_account',
                        lambda db, account: {'reset': True, 'result': 'reset',
                                             'next_available_at': '2026-11-27T10:00:00Z'})
    r = client.post(f'/accounts/{a}/reset_limit')
    assert r.status_code == 200
    body = r.get_json()
    assert body['ok'] is True and body['reset'] is True
    assert body['result'] == 'reset'


def test_reset_limit_route_unavailable(client, monkeypatch):
    a = _add(app_module._db, org_uuid='org-1')
    monkeypatch.setattr(resetter, 'reset_account',
                        lambda db, account: {'reset': False, 'result': 'unavailable',
                                             'next_available_at': '2026-11-22T10:00:00Z'})
    r = client.post(f'/accounts/{a}/reset_limit')
    assert r.status_code == 200
    body = r.get_json()
    assert body['reset'] is False
    assert body['next_available_at'] == '2026-11-22T10:00:00Z'


def test_reset_limit_route_unknown_account_404(client):
    r = client.post('/accounts/999999/reset_limit')
    assert r.status_code == 404


def test_reset_limit_route_api_error_maps_502(client, monkeypatch):
    a = _add(app_module._db, org_uuid='org-1')

    def boom(db, account):
        raise auf.UsageApiError('claim failed', status=429)

    monkeypatch.setattr(resetter, 'reset_account', boom)
    r = client.post(f'/accounts/{a}/reset_limit')
    assert r.status_code == 502
    assert 'error' in r.get_json()


def test_reset_limit_route_unexpected_error_hides_message(client, monkeypatch):
    a = _add(app_module._db, org_uuid='org-1')

    def boom(db, account):
        raise RuntimeError('secret-token-xyz must not leak')

    monkeypatch.setattr(resetter, 'reset_account', boom)
    r = client.post(f'/accounts/{a}/reset_limit')
    assert r.status_code == 500
    body = r.get_json()
    assert 'secret-token-xyz' not in body['error']
    assert 'RuntimeError' in body['error']


def test_reset_status_route(client, monkeypatch):
    a = _add(app_module._db, org_uuid='org-1')
    monkeypatch.setattr(resetter, 'get_reset_status',
                        lambda db, account: dict(AVAILABLE, ineligible_reason=None))
    r = client.get(f'/accounts/{a}/reset_status')
    assert r.status_code == 200
    assert r.get_json()['status']['available'] is True


def test_reset_status_route_none_when_unsupported(client, monkeypatch):
    a = _add(app_module._db, org_uuid='org-1')
    monkeypatch.setattr(resetter, 'get_reset_status', lambda db, account: None)
    r = client.get(f'/accounts/{a}/reset_status')
    assert r.status_code == 200
    assert r.get_json()['status'] is None


def test_add_account_stores_org_uuid(client, monkeypatch):
    monkeypatch.setattr(app_module.oauth_flow, 'exchange_code',
                        lambda code, verifier: {'access_token': 'AT',
                                                'refresh_token': 'RT',
                                                'expires_at': FAR})
    monkeypatch.setattr(app_module.oauth_flow, 'fetch_profile',
                        lambda tok: {'email': 'n@x.com', 'account_type': 'max',
                                     'organization_uuid': 'org-new'})
    with client.session_transaction() as sess:
        sess['oauth_verifier'] = 'v'
        sess['oauth_state'] = 'st'
    r = client.post('/accounts/add',
                    data={'action': 'complete', 'code': 'abc#st', 'label': 'n'})
    assert r.status_code == 200
    acc_id = r.get_json()['id']
    assert app_module._db.get_account_for_primer(acc_id)['organization_uuid'] == 'org-new'


# ---- Layer 6: accounts template (mirrors test_accounts_template.py style) ----

BASE = os.path.dirname(os.path.abspath(__file__))


def _read(rel):
    with open(os.path.join(BASE, rel), encoding='utf-8') as f:
        return f.read()


def test_reset_limit_button_present():
    html = _read('templates/accounts.html')
    assert 'resetLimit({{ a.id }})' in html
    assert '>Reset limit<' in html


def test_reset_limit_js_handler_checks_status_first():
    """The handler must read reset_status before claiming — a reset is a limited
    resource, so the confirm dialog has to show real availability, and an
    unavailable reset must never be claimed."""
    html = _read('templates/accounts.html')
    assert 'async function resetLimit(' in html
    assert '/reset_status' in html
    assert '/reset_limit' in html
