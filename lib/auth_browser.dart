library googleapis_auth.html;

import 'dart:async';
import 'package:http_base/http_base_html.dart' as http;

import 'oauth2.dart';
import 'src/oauth2_flows/implicit.dart';

export 'oauth2.dart';

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
Future<BrowserOAuth2Flow> createImplicitBrowserFlow(
    ClientId clientId, List<String> scopes, {http.RequestHandler baseClient}) {
  if (baseClient == null) baseClient = new http.Client();

  var flow = new ImplicitFlow(clientId.identifier, scopes);
  return flow.initialize().then(
      (_) => new BrowserOAuth2Flow._(flow, scopes, baseClient));
}


/// Used for obtaining oauth2 access credentials.
class BrowserOAuth2Flow {
  final ImplicitFlow _flow;
  final List<String> _scopes;
  final http.RequestHandler _client;

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
    return _flow.login(immediate: !forceUserConsent).then((accessToken) {
      return new AccessCredentials(accessToken, null, _scopes);
    });
  }

  /// Obtains [AccessCredentials] and returns an authenticated HTTP client.
  ///
  /// After obtaining access credentials, this function will return an HTTP
  /// client (see typedef [http.RequestHandler]). HTTP requests made on the
  /// returned client will get an additional `Authorization` header with the
  /// `AccessCredentials` obtained.
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
  Future<http.RequestHandler> clientViaUserConsent(
      {bool forceUserConsent: true}) {
    return obtainAccessCredentialsViaUserConsent(
        forceUserConsent: forceUserConsent).then((credentials) {
      var authClient = authenticatedClient(_client, credentials);
      return (http.Request request) {
        if (!credentials.accessToken.hasExpired) {
          return authClient(request);
        } else {
          return _flow.login(immediate: true).then((accessToken) {
            credentials = new AccessCredentials(accessToken, null, _scopes);
            authClient = authenticatedClient(_client, credentials);
            return authClient(request);
          });
        }
      };
    });
  }
}
