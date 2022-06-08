"""
flask_csp.extension
"""

import logging

from .core import get_csp_options, set_csp_header

from .simple.views import CSP_BP as simple_bp

try:
    from .sqlalchemy.views import CSP_BP as sqlalchemy_bp
    SQLALCHEMY = True
except ImportError:
    SQLALCHEMY = False

LOG = logging.getLogger(__name__)


class CSP:
    """
    Initializes Content Security Policies for the application. The
    arguments are identical to :py:func:`csp`.

    The settings for CSP are determined in the following order

    1. Resource level settings (e.g when passed as a dictionary)
    2. Keyword argument settings
    3. App level configuration settings (e.g. CSP_*)
    4. Default settings

    """

    _options = {}
    _receiver_prefix = None
    _sqlalchemy = False

    def __init__(self, app=None, *, receiver_prefix=None, sqlalchemy=None, **kwargs):
        """CSP initializer"""

        self._options = kwargs
        self._receiver_prefix = receiver_prefix
        self._sqlalchemy = sqlalchemy

        if app is not None:
            self.init_app(app, receiver_prefix=receiver_prefix, sqlalchemy=sqlalchemy, **kwargs)

    def init_app(self, app, *, receiver_prefix=None, sqlalchemy=None, **kwargs):
        """App initialization for the extension"""

        # The resources and options may be specified in the App Config, the CSP constructor
        # or the kwargs to the call to init_app.
        self._options = get_csp_options(app, self._options, kwargs)

        if receiver_prefix is not None:
            self._receiver_prefix = receiver_prefix
        if sqlalchemy is not None:
            self._sqlalchemy = sqlalchemy

        app.after_request(self.after_request)

        # These error handlers will still respect the behavior of the route
        if self._options.get('intercept_exceptions', True):
            def _after_request_decorator(f):  # pylint: disable=invalid-name
                def wrapped_function(*args, **kwargs):
                    return self.after_request(app.make_response(f(*args, **kwargs)))
                return wrapped_function

            if hasattr(app, 'handle_exception'):
                app.handle_exception = _after_request_decorator(
                    app.handle_exception)
                app.handle_user_exception = _after_request_decorator(
                    app.handle_user_exception)

        if self._receiver_prefix is None:
            LOG.info(
                'Report receiving is disabled. To enable automatically, set `receiver_prefix`.')
            return

        if self._sqlalchemy:
            if not SQLALCHEMY:
                raise ValueError(
                    'Cannot load SqlAlchemy CSP views. SqlAlchemy is not available')

            app.register_blueprint(sqlalchemy_bp, prefix=self._receiver_prefix)

        else:
            app.register_blueprint(simple_bp, prefix=self._receiver_prefix)

    def after_request(self, resp):
        """The after request handler for the extension"""

        return set_csp_header(resp, self._options)
