# -*- coding: utf-8 -*-
"""
flask_csp.core
~~~~
Core functionality shared between the extension and the decorator.
"""

import logging

from flask import current_app
from werkzeug.datastructures import Headers, MultiDict

from .constants import Directive, FLASK_CSP_EVALUATED, DEFAULT_OPTIONS
from .policy import ReportGroup, ReportTo, ContentSecurityPolicy, ReportOnlyPolicy, load_directive


LOG = logging.getLogger(__name__)


def set_csp_header(resp, options):
    """
    Performs the actual evaluation of Flask-CSP options and actually
    modifies the response object.

    This function is used both in the decorator and the after_request
    callback
    """

    # If CSP has already been evaluated via the decorator, skip
    if hasattr(resp, FLASK_CSP_EVALUATED):
        LOG.debug('CSP has been already evaluated, skipping')
        return resp

    setattr(resp, FLASK_CSP_EVALUATED, True)

    # Some libraries, like OAuthlib, set resp.headers to non Multidict
    # objects (Werkzeug Headers work as well). This is a problem because
    # headers allow repeated values.
    if (not isinstance(resp.headers, Headers)
           and not isinstance(resp.headers, MultiDict)):
        resp.headers = MultiDict(resp.headers)

    non_directive_options = ['report_only',]
    header = (ReportOnlyPolicy if options.get('report_only', False) else ContentSecurityPolicy)()
    for option, restrictions in options.items():
        if option in non_directive_options or not restrictions:
            continue
        if not isinstance(restrictions, (list, set, tuple, )):
            restrictions = [restrictions]
        header.add(load_directive(option, *restrictions))

    LOG.debug('Settings CSP header: %s', header.value)
    resp.headers.add(header.key, header.value)

    if options.get('report_to'):
        report_to = ReportTo()
        report_groups = options['report_to']
        if not isinstance(report_groups, (list, set, tuple,)):
            report_groups = [report_groups]
        for group in report_groups:
            report_to.add(
                ReportGroup(group['name'],
                            group['endpoints'],
                            max_age=group.get('max_age', None))
            )

        resp.headers.add(report_to.key, report_to.value)

    return resp


def get_csp_options(app, *dicts):
    """
    Compute CSP options for an application by combining the DEFAULT_OPTIONS,
    the app's configuration-specified options and any dictionaries passed. The
    last specified option wins.
    """

    options = DEFAULT_OPTIONS.copy()
    options.update(get_app_kwarg_dict(app))
    if dicts:
        for dict_ in dicts:
            options.update(dict_)

    return options


def get_app_kwarg_dict(app=None):
    """Returns the dictionary of CSP specific app configurations."""

    app = (app or current_app)

    # In order to support blueprints which do not have a config attribute
    app_config = getattr(app, 'config', {})

    return {
        k.name.lower(): app_config.get(f'CSP_{k.name}')
        for k in Directive
        if app_config.get(f'CSP_{k.name}') is not None
    }
