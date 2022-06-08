"""
tests.test_extension
"""

import pytest

from flask import url_for

from flask_csp import CSP


@pytest.mark.parametrize('test_app, state', [
    (pytest.lazy_fixture('base_app'), False,),
    (pytest.lazy_fixture('app'), True,),
    (pytest.lazy_fixture('receiver_app'), True,),
])
def test_after_request_added(test_app, state):
    """Ensure that the simple CSP extension adds the after request processor"""

    after_request_found = False
    for k,v in test_app.after_request_funcs.items():
        for i in v:
            if i.__qualname__ == 'CSP.after_request':
                after_request_found = True
                break

    assert after_request_found == state


@pytest.mark.parametrize('test_app, state', [
    (pytest.lazy_fixture('base_app'), False,),
    (pytest.lazy_fixture('app'), False,),
    (pytest.lazy_fixture('receiver_app'), True,),
])
def test_receiver_route_added(test_app, state):
    """Ensure that the receiver blueprint does not get added when no prefix is provided"""

    receiver_route_found = False
    for rule in test_app.url_map.iter_rules():
        if rule.rule == '/report':
            receiver_route_found = True
            break

    assert receiver_route_found == state


@pytest.mark.parametrize('test_app, route, csp_state, csp_report_state', [
    (pytest.lazy_fixture('app'), '/undecorated', "default-src 'self'", None,),
    (pytest.lazy_fixture('receiver_app'), '/undecorated', "default-src 'self'", None,),
    (pytest.lazy_fixture('report_only_app'), '/undecorated', None, "default-src 'self'; report-uri https://example.com/report/receiver",),
    (pytest.lazy_fixture('app'), '/extension/decorated/report-only', None, "default-src 'self'; report-uri https://example.com/csp/receiver",),
    (pytest.lazy_fixture('receiver_app'), '/extension/decorated/report-only', None, "default-src 'self'; report-uri https://example.com/csp/receiver",),
    (pytest.lazy_fixture('report_only_app'), '/report-only/extension/decorated', "default-src 'self'", None,),
])
def test_extension_csp_header(test_app, route, csp_state, csp_report_state):
    """Ensure that the CSP extension adds the CSP header appropriately"""

    with test_app.app_context():
        with test_app.test_client() as c:
            rv = c.get(route)
            assert rv.status_code == 200
            assert rv.headers.get('Content-Security-Policy') == csp_state
            assert rv.headers.get('Content-Security-Policy-Report-Only') == csp_report_state
