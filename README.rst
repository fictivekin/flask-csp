Flask-CSP
=========

A Flask extension for including Content-Security-Policy (CSP) headers in responses that Flask builds.

There are 2 ways to use this extension:

- globally, covering the entire app with a single policy
- individual views, using a decorator that can have specific policies for each view


Quick Start
-----------

.. code:: bash

    $ pip3 install flask-csp


App-level extension
-------------------

.. code:: python

    from flask import Flask
    from flask_csp import CSP

    app = Flask(__name__)
    CSP(app)

    @app.route("/")
    def index():
      return "Hello, with a very simple default CSP policy!"


As a decorator
--------------

.. code:: python

    from flask import Flask
    from flask_csp import csp

    app = Flask(__name__)

    @app.route("/")
    @csp()
    def index():
      return "Hello, with a very simple default CSP policy!"


