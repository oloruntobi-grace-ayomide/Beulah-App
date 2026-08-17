import os
import requests

TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY')


def is_honeypot_triggered(data):
    """
    data: request.form (form posts) or request.get_json() dict (AJAX/JSON posts).
    True means a bot filled in the hidden field — a real visitor never would.
    """
    return bool((data.get('website') or '').strip())


def verify_turnstile(token, remote_ip=None):
    """
    token: the value from the Turnstile widget (turnstile.getResponse()).
    Returns True only if Cloudflare confirms the token is valid and unused.
    Fails closed — any error talking to Cloudflare counts as verification failure,
    not as "let it through."
    """
    if not token:
        return False
    try:
        resp = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={
                'secret': TURNSTILE_SECRET_KEY,
                'response': token,
                'remoteip': remote_ip or '',
            },
            timeout=10
        )
        return resp.json().get('success', False)
    except Exception:
        return False