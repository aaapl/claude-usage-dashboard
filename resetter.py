"""Manual rate-limit reset ("restart"): claim Anthropic's juniper_tide program.

Mirrors primer.py — trigger-agnostic orchestration used by the web button. The
flow matches what the Claude Code CLI does: read usage with at_wall=1 (the
response then carries the juniper_tide status block), and when a reset is
available POST /api/organizations/<uuid>/reset_rate_limits. Claiming consumes
one of the account's limited resets, so the status gate runs server-side here
too — a stale button click never wastes one.
"""
import account_session
import api_usage_fetcher as auf
import oauth_flow


def get_reset_status(db, account):
    """Mapped juniper_tide status for one account, or None when the API doesn't
    expose the block (feature off / unknown shape). Raises auf.UsageApiError on
    an API failure."""
    api = account_session.call_with_401_retry(
        db, account, lambda tok: auf._http_get_usage(tok, at_wall=True))
    return auf.map_reset_status(api)


def _ensure_org_uuid(db, account):
    """The claim URL needs the organization uuid; fetch + persist it lazily for
    accounts added before the column existed. The token was just used (and
    refreshed if needed) by the status read, so a plain profile GET suffices."""
    if account.get('organization_uuid'):
        return account['organization_uuid']
    try:
        profile = oauth_flow.fetch_profile(account['access_token'])
    except oauth_flow.OAuthError as e:
        raise auf.UsageApiError(f'could not resolve organization: {e}') from e
    org_uuid = profile.get('organization_uuid')
    if not org_uuid:
        raise auf.UsageApiError('account profile has no organization uuid')
    db.set_account_org_uuid(account['id'], org_uuid)
    account['organization_uuid'] = org_uuid
    return org_uuid


def reset_account(db, account):
    """Claim a rate-limit reset for one account if one is available.

    Returns {'reset': bool, 'result': str, 'next_available_at': str|None}.
    result: 'reset' (success), 'unavailable'/'ineligible' (client-side status
    gate), or whatever the claim endpoint answered ('already_used',
    'not_limited', 'ineligible', ...).
    Raises auf.UsageApiError on an API failure (route maps it to HTTP 502).
    """
    api = account_session.call_with_401_retry(
        db, account, lambda tok: auf._http_get_usage(tok, at_wall=True))
    status = auf.map_reset_status(api)
    # status None = unknown (Team accounts answer juniper_tide=null on the OAuth
    # surface, live finding 2026-11-20). Unknown does NOT block: the server is
    # the real gate and an ineligible claim consumes nothing. Only a KNOWN
    # unavailable/ineligible status short-circuits client-side.
    if status is not None and not status['available']:
        result = 'unavailable' if status['eligible'] else 'ineligible'
        return {'reset': False, 'result': result,
                'next_available_at': status['next_available_at']}

    org_uuid = _ensure_org_uuid(db, account)
    out = account_session.call_with_401_retry(
        db, account, lambda tok: auf.claim_rate_limit_reset(tok, org_uuid))
    result = out.get('result') if isinstance(out.get('result'), str) else 'unknown'
    next_at = out.get('next_available_at')

    # Best-effort post-claim snapshot so the dashboard shows the freed window
    # right away; a read failure must never turn a successful claim into an error.
    if result == 'reset':
        try:
            api2 = account_session.call_with_401_retry(
                db, account, auf._http_get_usage)
            db.insert_snapshot(auf.build_snapshot(api2, account))
            db.record_account_poll(account['id'], error=None)
        except auf.UsageApiError:
            pass
    return {'reset': result == 'reset', 'result': result,
            'next_available_at': next_at if isinstance(next_at, str) else None}
