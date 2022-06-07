"""
flask_csp.sqlalchemy.models
"""

from sqlalchemy import db, func  # pylint: disable=import-error


class CspReport(db.Model):  # pylint: disable=too-few-public-methods
    """

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

    Reference:

    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only

    """

    __tablename__ = "csp_reports"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=func.now(), nullable=False)

    blocked_uri = db.Column(db.String, nullable=False)
    disposition = db.Column(db.String, nullable=False)
    document_uri = db.Column(db.String, nullable=False)
    effective_directive = db.Column(db.String)
    original_policy = db.Column(db.String, nullable=False)
    referrer = db.Column(db.String)
    script_sample = db.Column(db.String)
    status_code = db.Column(db.Integer)
    violated_directive = db.Column(db.String)
