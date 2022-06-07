# -*- coding: utf-8 -*-
"""
flask_csp.decorator
~~~~
A decorator to protect a single Flask route with CSP
"""

from functools import update_wrapper
import logging

from flask import make_response, current_app

from .core import get_csp_options, set_csp_header


LOG = logging.getLogger(__name__)


def csp(*args, **kwargs):  # pylint: disable=unused-argument
    """
    This function is the decorator which is used to wrap a Flask route with.
    """

    _options = kwargs

    def decorator(f):  # pylint: disable=invalid-name
        LOG.debug("Enabling %s for csp using options: %s", f, _options)

        def wrapped_function(*args, **kwargs):
            # Handle setting of Flask-CSP parameters
            options = get_csp_options(current_app, _options)

            resp = make_response(f(*args, **kwargs))

            return set_csp_header(resp, options)

        return update_wrapper(wrapped_function, f)
    return decorator
