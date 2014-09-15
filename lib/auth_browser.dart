// Copyright (c) 2014, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library googleapis_auth.auth_browser;

import 'dart:async';
import 'package:http/http.dart';
import 'package:http/browser_client.dart';

import 'auth.dart';
import 'src/auth_http_utils.dart';
import 'src/oauth2_flows/implicit.dart';
import 'src/http_client_base.dart';

export 'auth.dart';

/// Will create and complete with a [BrowserOAuth2Flow] object.
///
/// This function will perform an implicit browser based oauth2 flow.
///
/// It will load Google's `gapi` library and initialize it. After initialization
/// it will complete with a [BrowserOAuth2Flow] object. The flow object can be
/// used to obtain `AccessCredentials` or an authenticated HTTP client.
///
/// If loading or initializing the `gapi` library results in an error, this
/// future will complete with an error.
///
/// If [baseClient] is not given, one will be automatically created. It will be
/// used for making authenticated HTTP requests. See [BrowserOAuth2Flow].
///
/// The [ClientId] can be obtained in the Google Cloud Console.
///
/// The user is responsible for closing the returned [BrowserOAuth2Flow] object.
/// Closing the returned [BrowserOAuth2Flow] will not close [baseClient]
/// if one was given.
Future<BrowserOAuth2Flow> createImplicitBrowserFlow(
    ClientId clientId, List<String> scopes, {Client baseClient}) {
  if (baseClient == null) {
    baseClient = new RefCountedClient(new BrowserClient(), initialRefCount: 1);
  } else {
    baseClient = new RefCountedClient(baseClient, initialRefCount: 2);
  }

  var flow = new ImplicitFlow(clientId.identifier, scopes);
  return flow.initialize().catchError((error, stack) {
    baseClient.close();
    return new Future.error(error, stack);
  }).then((_) => new BrowserOAuth2Flow._(flow, scopes, baseClient));
}


/// Used for obtaining oauth2 access credentials.
///
/// Warning:
///
/// The methods `obtainAccessCredentialsViaUserConsent` and
/// `clientViaUserConsent` try to open a popup window for the user authorization
/// dialog.
///
/// In order to prevent browsers from blocking the popup window, these
/// methods should only be called inside an event handler, since most
/// browsers do not block popup windows created in response to a user
/// interaction.
class BrowserOAuth2Flow {
  final ImplicitFlow _flow;
  final List<String> _scopes;
  final RefCountedClient _client;

  bool _wasClosed = false;

  /// The HTTP client passed in will be closed if `close` was called and all
  /// generated HTTP clients via [clientViaUserConsent] were closed.
  BrowserOAuth2Flow._(this._flow, this._scopes, this._client);

  /// Obtain oauth2 [AccessCredentials].
  ///
  /// If [forceUserConsent] is `true`, a new popup window will be created. The
  /// user will be presented with the list of scopes that this application
  /// would like to access on his behalf. The user either approves the request
  /// for permission for the application or denies it.
  ///
  /// If [forceUserConsent] is `false`, it will try to obtain access credentials
  /// without user interaction.
  ///
  /// The returned future will complete with `AccessCredentials` if the user
  /// has given the application access to it's data. Otherwise the future will
  /// complete with a `UserConsentException`.
  ///
  /// In case another error occurs the returned future will complete with an
  /// `Exception`.
  Future<AccessCredentials> obtainAccessCredentialsViaUserConsent(
      {bool forceUserConsent: true}) {
    _ensureOpen();
    return _flow.login(immediate: !forceUserConsent).then((accessToken) {
      return new AccessCredentials(accessToken, null, _scopes);
    });
  }

  /// Obtains [AccessCredentials] and returns an authenticated HTTP client.
  ///
  /// After obtaining access credentials, this function will return an HTTP
  /// [Client]. HTTP requests made on the returned client will get an
  /// additional `Authorization` header with the `AccessCredentials` obtained.
  ///
  /// In case the `AccessCredentials` expire, it will try to obtain new ones
  /// without user consent.
  ///
  /// See [obtainAccessCredentialsViaUserConsent] for how credentials will be
  /// obtained. Errors from [obtainAccessCredentialsViaUserConsent] will be let
  /// through to the returned `Future` of this function and to the returned
  /// HTTP client (in case of credential refreshes).
  ///
  /// The returned HTTP client will forward errors from lower levels via it's
  /// `Future<Response>` or it's `Response.read()` stream.
  ///
  /// The user is responsible for closing the returned HTTP client.
  Future<AutoRefreshingAuthClient> clientViaUserConsent(
      {bool forceUserConsent: true}) {
    _ensureOpen();
    return obtainAccessCredentialsViaUserConsent(
        forceUserConsent: forceUserConsent).then((credentials) {
      _client.acquire();
      return new _AutoRefreshingBrowserClient(
          _client, credentials, _scopes, _flow);
    });
  }

  /// Will close this [BrowserOAuth2Flow] object and the HTTP [Client] it is
  /// using.
  ///
  /// The clients obtained via [clientViaUserConsent] will continue to work.
  /// After this flow object and all obtained clients were closed the underlying
  /// HTTP client will be closed as well.
  ///
  /// After calling this `close` method, calls to [clientViaUserConsent] and
  /// [obtainAccessCredentialsViaUserConsent] will fail.
  void close() {
    _ensureOpen();
    _wasClosed = true;
    _client.close();
  }

  void _ensureOpen() {
    if (_wasClosed) {
      throw new StateError('BrowserOAuth2Flow has already been closed.');
    }
  }
}


class _AutoRefreshingBrowserClient extends AutoRefreshDelegatingClient {
  AccessCredentials credentials;
  ImplicitFlow _flow;
  List<String> _scopes;
  Client _authClient;

  _AutoRefreshingBrowserClient(Client client, this.credentials, this._scopes,
      this._flow) : super(client) {
    _authClient = authenticatedClient(baseClient, credentials);
  }

  Future<StreamedResponse> send(BaseRequest request) {
    if (!credentials.accessToken.hasExpired) {
      return _authClient.send(request);
    } else {
      return _flow.login(immediate: true).then((accessToken) {
        credentials = new AccessCredentials(accessToken, null, _scopes);
        notifyAboutNewCredentials(credentials);
        _authClient = authenticatedClient(baseClient, credentials);
        return _authClient.send(request);
      });
    }
  }
}
