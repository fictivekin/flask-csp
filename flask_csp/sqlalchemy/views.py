"""
flask_csp.views.sqlalchemy
"""

import logging

from flask import abort, request, make_response, render_template, Blueprint

try:
    from sentry import capture_exception
    SENTRY = True
except ImportError:
    SENTRY = False

from ..utils import get_submitted_report
from .models import CspReport


LOG = logging.getLogger('flask_csp.receiver')
CSP_BP = Blueprint('csp', __name__)

# This will need to be set by the app's db variable in order to actually work
DB = None


@CSP_BP.route('/report', methods=['POST'])
def receiver():
    """
    A simple receiver that outputs CSP reports to the log

    Example CSP report:

        {
          "csp-report": {
            "document-uri": "http://example.com/signup.html",
            "referrer": "",
            "blocked-uri": "http://example.com/css/style.css",
            "violated-directive": "style-src cdn.example.com",
            "original-policy":
                "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",
            "disposition": "report"
          }
        }

    """

    csp_report = get_submitted_report()

    # These 2 try blocks are separate to enable returning a 400 or 422 depending on
    # if the provided data was broken or there was an error saving the report to the db
    try:
        report = CspReport(
            blocked_uri=csp_report['blocked-uri'],
            disposition=csp_report['disposition'],
            document_uri=csp_report['document-uri'],
            effective_directive=csp_report.get('effective-directive'),
            original_policy=csp_report['original-policy'],
            referrer=csp_report.get('referrer'),
            script_sample=csp_report.get('script-sample'),
            status_code=int(csp_report.get('status-code')),
            violated_directive=csp_report.get('violated-directive'),
        )

    except Exception as exc:  # pylint: disable=broad-except
        if SENTRY:
            capture_exception(exc)

        LOG.exception(exc)
        return abort(400)

    try:
        with DB.session.begin():
            DB.session.add(report)

    except Exception as exc:  # pylint: disable=broad-except
        if SENTRY:
            capture_exception(exc)

        LOG.exception(exc)
        return abort(422)

    return make_response('', 204)


@CSP_BP.route('/reports/review', methods=['GET','POST'])
def review():
    """
    Lists and allows searching of saved CSP reports
    """

    if request.method == 'POST':
        filters = []
        for filter_, value in request.values.items():
            if not value:
                continue

            if filter_ == 'before':
                filters.append(CspReport.ts.lte(value))

            elif filter_ == 'after':
                filters.append(CspReport.ts.gte(value))

            elif filter_ == 'disposition':
                filters.append(CspReport.disposition == value)

            elif filter_ == 'document-uri':
                filters.append(CspReport.document_uri.ilike(f'%{value}%'))

            elif filter_ == 'blocked-uri':
                filters.append(CspReport.blocked_uri.ilike(f'%{value}%'))

            elif filter_ == 'referrer':
                filters.append(CspReport.referrer.ilike(f'%{value}%'))

            # else: not a parameter that we care about

    reports = CspReport.query.order_by(CspReport.id.desc()).all()

    return render_template('reports/list.html', reports=reports)
