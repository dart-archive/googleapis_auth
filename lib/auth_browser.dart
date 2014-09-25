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

/// Obtains a HTTP client which uses the given [apiKey] for making HTTP
/// requests.
///
/// Note that the returned client should *only* be used for making HTTP requests
/// to Google Services. The [apiKey] should not be disclosed to third parties.
///
/// The user is responsible for closing the returned HTTP [Client].
/// Closing the returned [Client] will not close [baseClient].
Client clientViaApiKey(String apiKey, {Client baseClient}) {
  if (baseClient == null) {
    baseClient = new BrowserClient();
  } else {
    baseClient = nonClosingClient(baseClient);
  }
  return new ApiKeyClient(baseClient, apiKey);
}

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
  }).then((_) => new BrowserOAuth2Flow._(flow, baseClient));
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
  final RefCountedClient _client;

  bool _wasClosed = false;

  /// The HTTP client passed in will be closed if `close` was called and all
  /// generated HTTP clients via [clientViaUserConsent] were closed.
  BrowserOAuth2Flow._(this._flow, this._client);

  /// Obtain oauth2 [AccessCredentials].
  ///
  /// If [forceUserConsent] is `true`, a new popup window will be created. The
  /// user will be presented with the list of scopes that this application
  /// would like to access on his behalf. The user either approves the request
  /// for permission for the application or cancels. If the user has already
  /// granted access, the popup might close automatically again.
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
    return _flow.login(immediate: !forceUserConsent);
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
        forceUserConsent: forceUserConsent).then(_clientFromCredentials);
  }

  /// Obtains [AccessCredentials] and an authorization code which can be
  /// exchanged for permanent access credentials.
  ///
  /// Use case:
  /// A web application might want to get consent for accessing data on behalf
  /// of a user. The client part is a dynamic webapp which wants to open a
  /// popup which asks the user for consent. The webapp might want to use the
  /// credentials to make API calls, but the server may want to have offline
  /// access to user data as well.
  Future<HybridFlowResult> runHybridFlow({bool forceUserConsent: true}) {
    _ensureOpen();

    buildHybridFlowResult(credentials, code)
        => new HybridFlowResult(this, credentials, code);

    return _flow.loginHybrid(immediate: !forceUserConsent).then((List tuple) {
      assert (tuple.length == 2);
      return new HybridFlowResult(this, tuple[0], tuple[1]);
    });
  }

  /// Will close this [BrowserOAuth2Flow] object and the HTTP [Client] it is
  /// using.
  ///
  /// The clients obtained via [clientViaUserConsent] will continue to work.
  /// The client obtained via `newClient` of obtained [HybridFlowResult] objects
  /// will continue to work.
  ///
  /// After this flow object and all obtained clients were closed the underlying
  /// HTTP client will be closed as well.
  ///
  /// After calling this `close` method, calls to [clientViaUserConsent],
  /// [obtainAccessCredentialsViaUserConsent] and to `newClient` on returned
  /// [HybridFlowResult] objects will fail.
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

  AutoRefreshingAuthClient _clientFromCredentials(AccessCredentials cred) {
    _ensureOpen();
    _client.acquire();
    return new _AutoRefreshingBrowserClient(_client, cred, _flow);
  }
}

/// Represents the result of running a browser based hybrid flow.
///
/// The `credentials` field holds credentials which can be used on the client
/// side. The `newClient` function can be used to make a new authenticated HTTP
/// client using these credentials.
///
/// The `authorizationCode` can be sent to the server, which knows the
/// "client secret" and can exchange it with long-lived access credentials.
///
/// See the `obtainAccessCredentialsViaCodeExchange` function in the
/// `googleapis_auth.auth_io` library for more details on how to use the
/// authorization code.
class HybridFlowResult {
  final BrowserOAuth2Flow _flow;

  /// Access credentials for making authenticated HTTP requests.
  final AccessCredentials credentials;

  /// The authorization code received from the authorization endpoint.
  ///
  /// The auth code can be used to receive permanent access credentials.
  /// This requires a confidential client which can keep a secret.
  final String authorizationCode;

  HybridFlowResult(this._flow, this.credentials, this.authorizationCode);

  AutoRefreshingAuthClient newClient() {
    _flow._ensureOpen();
    return _flow._clientFromCredentials(credentials);
  }
}


class _AutoRefreshingBrowserClient extends AutoRefreshDelegatingClient {
  AccessCredentials credentials;
  ImplicitFlow _flow;
  Client _authClient;

  _AutoRefreshingBrowserClient(Client client, this.credentials, this._flow)
      : super(client) {
    _authClient = authenticatedClient(baseClient, credentials);
  }

  Future<StreamedResponse> send(BaseRequest request) {
    if (!credentials.accessToken.hasExpired) {
      return _authClient.send(request);
    } else {
      return _flow.login(immediate: true).then((newCredentials) {
        credentials = newCredentials;
        notifyAboutNewCredentials(credentials);
        _authClient = authenticatedClient(baseClient, credentials);
        return _authClient.send(request);
      });
    }
  }
}
