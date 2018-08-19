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

    credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

    client = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

    return channels_list_by_username(client,
    part='snippet,contentDetails,statistics',
    forUsername='GoogleDevelopers'), flask.redirect("user") # TO DO: Check if return properly!

    # return flsk.redirect("user")


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
    # Specify the state when creating the flow in the callback so that it can
  # verify the authorization server response.
  state = flask.session['state']
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('user_page', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store the credentials in the session.
  # ACTION ITEM for developers:
  #     Store user's access and refresh tokens in your data store if
  #     incorporating this code into your real app.
  credentials = flow.credentials
  flask.session['credentials'] = {
      'token': credentials.token,
      'refresh_token': credentials.refresh_token,
      'token_uri': credentials.token_uri,
      'client_id': credentials.client_id,
      'client_secret': credentials.client_secret,
      'scopes': credentials.scopes
  }

  # return flask.redirect(flask.url_for('index'))
  return render_template("user.html", name=name)

def channels_list_by_username(client, **kwargs):
  response = client.channels().list(
    **kwargs
  ).execute()

  return flask.jsonify(**response)

def channels_list_by_username(client, **kwargs):
  response = client.channels().list(
    **kwargs
  ).execute()

  return flask.jsonify(**response)


@note.route("/albums", methods=["POST", "GET"])
def user_album(name=None):

  return render_template("albums.html", name=name)


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    note.debug = True
    server = Server(note.wsgi_app)
    server.serve()
