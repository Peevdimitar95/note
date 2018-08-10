#!/usr/bin/python

from flask import Flask, render_template, request
from livereload import Server
import flask
import os
import httplib2
import sys

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from apiclient.discovery import build
from apiclient.errors import HttpError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import argparser, run_flow


CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'


note = Flask(__name__)

s_key = os.urandom(24)
note.secret_key = s_key


@note.route("/")
def index_page(name=None):
    if 'credentials' not in flask.session:
      # return flask.redirect('login')
      return flask.redirect("login")
    return flsk.redirect("user")


@note.route("/login")
def login(name=None):
    # Create a flow instance to manage the OAuth 2.0 Authorization Grant Flow
    # steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('user_page', _external=True)
    authorization_url, state = flow.authorization_url(
        # This parameter enables offline access which gives your application
        # both an access and refresh token.
        access_type='offline',
        # This parameter enables incremental auth.
        include_granted_scopes='true')

    # Store the state in the session so that the callback can verify that
    # the authorization server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


"""
@note.route("/create_account")
def create_acc(name=None):
    return render_template("create_account.html")
"""


@note.route("/user", methods=["POST", "GET"])
def user_page(name=None):
    # if request.method == "POST":
        # print ("Usr:  %s Pass: %s" % (request.form["username"], request.form["password"]))

    return render_template("user.html", name=name)


@note.route("/albums", methods=["POST", "GET"])
def user_album(name=None):
    return render_template("albums.html", name=name)


if __name__ == '__main__':
    note.debug = True
    server = Server(note.wsgi_app)
    server.serve()

