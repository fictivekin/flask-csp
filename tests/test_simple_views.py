"""
tests.test_simple_views
"""

import pytest

from flask import url_for


csp_content_type = {  # pylint: disable=invalid-name
    'Content-Type': 'application/csp-report',
}


@pytest.mark.parametrize('headers, csp_report, status_code', [
    (csp_content_type, pytest.lazy_fixture('minimal_csp_report'), 204,),
    (csp_content_type, pytest.lazy_fixture('full_csp_report'), 204,),
    ({}, pytest.lazy_fixture('minimal_csp_report'), 400,),
    ({}, pytest.lazy_fixture('full_csp_report'), 400,),
    (csp_content_type, {}, 400,),
    ({}, {}, 400,),
])
def test_simple_submission(receiver_app, headers, csp_report, status_code):
    """Ensure that the simple CSP report receiver accepts reports"""

    with receiver_app.app_context():
        with receiver_app.test_client() as c:
            rv = c.post(
                url_for('csp.receiver'),
                json=csp_report,
                headers=headers,
            )
            assert rv.status_code == status_code


def test_simple_review(receiver_app):
    """Ensure that the simple CSP report review does not work"""

    with receiver_app.app_context():
        with receiver_app.test_client() as c:
            rv = c.get(url_for('csp.review'))
            assert rv.status_code == 404
