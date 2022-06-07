"""

policy

"""
# pylint: disable=missing-function-docstring,too-few-public-methods,missing-class-docstring

import json
from enum import Enum

from .constants import Directive, FetchRestriction, SandboxRestriction, TrustedTypesRestriction


def is_allowed_enum_value(type_, item, allowed=None):
    if not isinstance(item, type_):
        try:
            item = type_[str(item).upper().replace('-','_')]
        except KeyError as exc:
            raise ValueError(f'Not a valid {type_.__name__}: {item}') from exc

    if allowed and item not in allowed:
        raise ValueError(f'{item.value} is not accepted. Can only be one of {str(allowed)}')

    return item

def is_allowed_directive(item, allowed=None):
    return is_allowed_enum_value(Directive, item, allowed)


def is_allowed_fetch_restriction(item, allowed=None):
    return is_allowed_enum_value(FetchRestriction, item, allowed)


def is_allowed_sandbox_restriction(item, allowed=None):
    return is_allowed_enum_value(SandboxRestriction, item, allowed)


def is_allowed_trustedtype_restriction(item, allowed=None):
    return is_allowed_enum_value(TrustedTypesRestriction, item, allowed)


class BaseDirective:
    """A base class for all Directives"""

    directive = None
    restrictions = []

    _allowed = list(Directive)

    def __init__(self, directive, *restrictions):
        self.directive = is_allowed_directive(directive, self._allowed)
        self.restrictions = []
        for restriction in restrictions:
            self.add(restriction)

    def __str__(self):
        restrictions = []

        for restriction in self.restrictions:
            if callable(restriction):
                restrictions.append(restriction())

            elif isinstance(restriction, Enum):
                restrictions.append(restriction.value)

            else:
                restrictions.append(str(restriction))

        return f'{self.directive.value} {" ".join(restrictions)}'

    def add(self, restriction):
        if not restriction:
            raise ValueError('Cannot add an empty restriction to a directive')

        if isinstance(self.restrictions, set):
            self.restrictions.add(restriction)

        elif isinstance(self.restrictions, list):
            self.restrictions.append(restriction)

        elif isinstance(self.restrictions, tuple):
            self.restrictions = self.restrictions + (restriction,)


class EmptyDirective(BaseDirective):
    """EmptyDirectives are a single command directive with no extra values"""

    _allowed = [
        Directive.UPGRADE_INSECURE_REQUESTS,
    ]

    def __str__(self):
        return self.directive.value

    def add(self, restriction):
        raise ValueError('You cannot add restrictions to an EmptyDirective')


class SimpleDirective(BaseDirective):
    """SimpleDirectives are single command directives with a single value"""

    _allowed = [
        Directive.REPORT_TO,
        Directive.REPORT_URI,
    ]

    def __str__(self):
        return f'{self.directive.value} {self.restrictions[0]}'

    def add(self, restriction):
        if not restriction:
            raise ValueError('Cannot add an empty restriction to a directive')

        if self.restrictions:
            raise ValueError('You cannot add multiple restrictions to a SimpleDirective.')

        super().add(restriction)


class SandboxDirective(BaseDirective):
    """SandboxDirectives are single command directives with multiple values from a special set"""

    _allowed = [
        Directive.SANDBOX,
    ]

    def __init__(self, *restrictions):
        super().__init__(Directive.SANDBOX)
        for restriction in restrictions:
            self.add(restriction)

    def add(self, restriction):
        if not restriction:
            raise ValueError('Cannot add an empty restriction to a directive')

        try:
            super().add(is_allowed_sandbox_restriction(restriction))

        except ValueError as exc:
            raise ValueError(
                f'{restriction} is not an allowed SANDBOX restriction') from exc


class TrustedTypesDirective(BaseDirective):
    """TrustedTypesDirectives are single command directives with multiple values"""

    _allowed = [
        Directive.TRUSTED_TYPES,
    ]

    def __init__(self, *restrictions):
        super().__init__(Directive.TRUSTED_TYPES)
        for restriction in restrictions:
            self.add(restriction)

    def add(self, restriction):
        if not restriction:
            raise ValueError('Cannot add an empty restriction to a directive')

        try:
            super().add(is_allowed_trustedtype_restriction(restriction))

        except ValueError:
            super().add(str(restriction))


class SourceDirective(BaseDirective):
    """
    SourceDirectives are single command directives with multiple values allowing freeform values
    """

    # pylint: disable=protected-access
    _allowed = [
        item
        for item in Directive
        if item not in TrustedTypesDirective._allowed +
            SandboxDirective._allowed +
            SimpleDirective._allowed +
            EmptyDirective._allowed
    ]


def load_directive(string, *restrictions):
    """Returns the appropriate *Directive class based on the provided data"""

    if isinstance(string, BaseDirective):
        return string

    directive = is_allowed_directive(string.lower())

    if directive in SourceDirective._allowed:  # pylint: disable=protected-access
        return SourceDirective(directive, *restrictions)

    if directive in SimpleDirective._allowed:  # pylint: disable=protected-access
        return SimpleDirective(directive, *restrictions)

    if directive in EmptyDirective._allowed:  # pylint: disable=protected-access
        return EmptyDirective(directive)

    if directive in SandboxDirective._allowed:  # pylint: disable=protected-access
        return SandboxDirective(*restrictions)

    if directive in TrustedTypesDirective._allowed:  # pylint: disable=protected-access
        return TrustedTypesDirective(*restrictions)

    raise ValueError(f'Unhandled directive type: {directive.value}')


class Header:
    @property
    def key(self):
        raise NotImplementedError()

    @property
    def value(self):
        raise NotImplementedError()

    def __str__(self):
        return f'{self.key}: {self.value}'


class ReportGroup:
    name = None
    max_age = 3600
    endpoints = []

    def __init__(self, name, endpoints, max_age=None):
        self.name = name
        self.endpoints = endpoints

        if max_age is not None and int(max_age) > 0:
            self.max_age = max_age

    def __str__(self):
        value = {
            "group": self.name,
            "max_age": self.max_age,
            "endpoints": [{"url": endpoint} for endpoint in self.endpoints],
        }
        return json.dumps(value)


class ReportTo(Header):

    key = 'Report-To'
    groups = []

    def __init__(self, *, groups=None):
        if groups is not None:
            if not isinstance(groups, (list, set, tuple, )):
                groups = [groups]

            self.groups = groups

        else:
            self.groups = []

    @property
    def value(self):
        return ','.join(self.groups)

    def add(self, group):
        if isinstance(group, (list, set, tuple,)):
            for item in group:
                self.add(item)

        elif isinstance(group, ReportGroup):
            self.groups.append(group)

        else:
            raise ValueError('Provided report group was invalid')


class ContentSecurityPolicy(Header):
    key = 'Content-Security-Policy'
    directives = []

    def __init__(self, *, directives=None):
        if directives is not None:
            if not isinstance(directives, (list, set, tuple,)):
                directives = [directives]

            self.directives = directives

        else:
            self.directives = []

    @property
    def value(self):
        return '; '.join([str(directive) for directive in self.directives])

    def add(self, directive):
        if isinstance(directive, (list, set, tuple,)):
            for item in directive:
                self.add(item)

        elif isinstance(directive, BaseDirective):
            self.directives.append(directive)

        else:
            raise ValueError('Provided directive was invalid')


class ReportOnlyPolicy(ContentSecurityPolicy):
    key = 'Content-Security-Policy-Report-Only'

    @property
    def value(self):
        if not filter(lambda item: item.directive == Directive.REPORT_TO, self.directives):
            raise ValueError('There must be a report-to directive when using a report-only policy!')

        return super().value
