library googleapis_auth.auth_io;

import 'dart:async';

import 'package:http_base/http_base_io.dart' as http;

import 'auth.dart';
import 'src/oauth2_flows/auth_code.dart';
import 'src/oauth2_flows/jwt.dart';
import 'src/oauth2_flows/metadata_server.dart';

export 'auth.dart';

/// Function for directing the user or it's user-agent to [uri].
///
/// The user is required to go to [uri] and either approve or decline the
/// application's request for access resources on his behalf.
typedef void PromptUserForConsent(String uri);


/// Function for directing the user or it's user-agent to [uri].
///
/// The user is required to go to [uri] and either approve or decline the
/// application's request for access resources on his behalf.
///
/// The user will be given an authorization code. This function should complete
/// with this authorization code. If the user declined to give access this
/// function should complete with an error.
typedef Future<String> PromptUserForConsentManual(String uri);


/// Obtains oauth2 credentials and returns an authenticated HTTP client.
///
/// See [obtainAccessCredentialsViaUserConsent] for specifics about the
/// arguments used for obtaining access credentials.
///
/// Once access credentials have been obtained, this function will complete
/// with an auto-refreshing HTTP client. Once the `AccessCredentials` expire
/// it will use it's refresh token (if available) to obtain new credentials.
/// See [autoRefreshingClient] for more information.
///
/// If [baseClient] is not given, one will be automatically created. It will be
/// used for making authenticated HTTP requests.
Future<http.RequestHandler> clientViaUserConsent(
    ClientId clientId,
    List<String> scopes,
    PromptUserForConsent userPrompt,
    {http.RequestHandler baseClient}) {
  if (baseClient == null) baseClient = new http.Client();

  var flow = new AuthorizationCodeGrantServerFlow(
      clientId, scopes, baseClient, userPrompt);

  return flow.run().then(
      (credentials) => autoRefreshingClient(clientId, credentials, baseClient));
}


/// Obtains oauth2 credentials and returns an authenticated HTTP client.
///
/// See [obtainAccessCredentialsViaUserConsentManual] for specifics about the
/// arguments used for obtaining access credentials.
///
/// Once access credentials have been obtained, this function will complete
/// with an auto-refreshing HTTP client. Once the `AccessCredentials` expire
/// it will use it's refresh token (if available) to obtain new credentials.
/// See [autoRefreshingClient] for more information.
///
/// If [baseClient] is not given, one will be automatically created. It will be
/// used for making authenticated HTTP requests.
Future<http.RequestHandler> clientViaUserConsentManual(
    ClientId clientId,
    List<String> scopes,
    PromptUserForConsentManual userPrompt,
    {http.RequestHandler baseClient}) {
  if (baseClient == null) baseClient = new http.Client();

  var flow = new AuthorizationCodeGrantManualFlow(
      clientId, scopes, baseClient, userPrompt);

  return flow.run().then(
      (credentials) => autoRefreshingClient(clientId, credentials, baseClient));
}


/// Obtains oauth2 credentials and returns an authenticated HTTP client.
///
/// See [obtainAccessCredentialsViaServiceAccount] for specifics about the
/// arguments used for obtaining access credentials.
///
/// Once access credentials have been obtained, this function will complete
/// with an auto-refreshing HTTP client. Once the `AccessCredentials` expire
/// it will obtain new access credentials.
///
/// If [baseClient] is not given, one will be automatically created. It will be
/// used for making authenticated HTTP requests and for obtaining access
/// credentials.
Future<http.RequestHandler> clientViaServiceAccount(
    ServiceAccountCredentials clientCredentials,
    List<String> scopes,
    {http.RequestHandler baseClient}) {
  if (baseClient == null) baseClient = new http.Client();

  var flow = new JwtFlow(clientCredentials.email,
                         clientCredentials.privateRSAKey,
                         scopes,
                         baseClient);

  return flow.run().then((credentials) {
    var authClient = authenticatedClient(baseClient, credentials);
    return (request) {
      if (!credentials.accessToken.hasExpired) {
        return authClient(request);
      } else {
        return flow.run().then((newCredentials) {
          credentials = newCredentials;
          authClient = authenticatedClient(baseClient, credentials);
          return authClient(request);
        });
      }
    };
  });
}


/// Obtains oauth2 credentials and returns an authenticated HTTP client.
///
/// See [obtainAccessCredentialsViaMetadataServer] for specifics about the
/// arguments used for obtaining access credentials.
///
/// Once access credentials have been obtained, this function will complete
/// with an auto-refreshing HTTP client. Once the `AccessCredentials` expire
/// it will obtain new access credentials.
///
/// If [baseClient] is not given, one will be automatically created. It will be
/// used for making authenticated HTTP requests and for obtaining access
/// credentials.
Future<http.RequestHandler> clientViaMetadataServer(
      {http.RequestHandler baseClient}) {
  if (baseClient == null) baseClient = new http.Client();

  var flow = new MetadataServerAuthorizationFlow(baseClient);
  return flow.run().then((credentials) {
    var authClient = authenticatedClient(baseClient, credentials);
    return (request) {
      if (!credentials.accessToken.hasExpired) {
        return authClient(request);
      } else {
        return flow.run().then((newCredentials) {
          credentials = newCredentials;
          authClient = authenticatedClient(baseClient, credentials);
          return authClient(request);
        });
      }
    };
  });
}


/// Obtain oauth2 [AccessCredentials] using the oauth2 authentication code flow.
///
/// The returned future will complete with `AccessCredentials` if the user
/// has given the application access to it's data. Otherwise the future will
/// complete with a `UserConsentException`.
///
/// In case another error occurs the returned future will complete with an
/// `Exception`.
///
/// [userPrompt] will be used for directing the user/user-agent to a URI. See
/// [PromptUserForConsent] for more information.
///
/// [client] will be used for obtaining `AccessCredentials` from an
/// authorization code.
///
/// The [ClientId] can be obtained in the Google Cloud Console.
Future<AccessCredentials> obtainAccessCredentialsViaUserConsent(
    ClientId clientId,
    List<String> scopes,
    http.RequestHandler client,
    PromptUserForConsent userPrompt) {
  return new AuthorizationCodeGrantServerFlow(
      clientId, scopes, client, userPrompt).run();
}


/// Obtain oauth2 [AccessCredentials] using the oauth2 authentication code flow.
///
/// The returned future will complete with `AccessCredentials` if the user
/// has given the application access to it's data. Otherwise the future will
/// complete with a `UserConsentException`.
///
/// In case another error occurs the returned future will complete with an
/// `Exception`.
///
/// [userPrompt] will be used for directing the user/user-agent to a URI. See
/// [PromptUserForConsentManual] for more information.
///
/// [client] will be used for obtaining `AccessCredentials` from an
/// authorization code.
///
/// The [ClientId] can be obtained in the Google Cloud Console.
Future<AccessCredentials> obtainAccessCredentialsViaUserConsentManual(
    ClientId clientId,
    List<String> scopes,
    http.RequestHandler client,
    PromptUserForConsentManual userPrompt) {
  return new AuthorizationCodeGrantManualFlow(
      clientId, scopes, client, userPrompt).run();
}


/// Obtain oauth2 [AccessCredentials] using service account credentials.
///
/// In case the service account has no access to the requested scopes or another
/// error occurs the returned future will complete with an `Exception`.
///
/// [client] will be used for obtaining `AccessCredentials`.
///
/// The [ServiceAccountCredentials] can be obtained in the Google Cloud Console.
Future<AccessCredentials> obtainAccessCredentialsViaServiceAccount(
   ServiceAccountCredentials clientCredentials,
   List<String> scopes, http.RequestHandler baseClient) {
  return new JwtFlow(clientCredentials.email,
                     clientCredentials.privateRSAKey,
                     scopes,
                     baseClient).run();
}


/// Obtain oauth2 [AccessCredentials] using the metadata API on ComputeEngine.
///
/// In case the VM was not configured with access to the requested scopes or an
/// error occurs the returned future will complete with an `Exception`.
///
/// [client] will be used for obtaining `AccessCredentials`.
///
/// No credentials are needed. But this function is only intended to work on a
/// Google Compute Engine VM with configured access to Google APIs.
Future<AccessCredentials> obtainAccessCredentialsViaMetadataServer(
    http.RequestHandler baseClient) {
  return new MetadataServerAuthorizationFlow(baseClient).run();
}



// TODO: User callback for obtaining/storing new [AccessCredentials]
