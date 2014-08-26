library googleapis_auth;

import 'dart:async';
import 'package:http/http.dart';

import '../auth.dart';
import 'http_client_base.dart';

/// Will close the underlying `http.Client` depending on a constructor argument.
class AuthenticatedClient extends DelegatingClient {
  final AccessCredentials credentials;

  AuthenticatedClient(Client client, this.credentials)
      : super(client, closeUnderlyingClient: false);

  Future<StreamedResponse> send(BaseRequest request) {
    // Make new request object and perform the authenticated request.
    var modifiedRequest = new RequestImpl(
        request.method, request.url, request.finalize());
    modifiedRequest.headers.addAll(request.headers);
    modifiedRequest.headers['Authorization'] =
        'Bearer ${credentials.accessToken.data}';
    return baseClient.send(modifiedRequest).then((response) {
      var wwwAuthenticate = response.headers['www-authenticate'];
      if (wwwAuthenticate != null) {
        return response.stream.drain().then((_) {
          throw new AccessDeniedException('Access was denied '
              '(www-authenticate header was: $wwwAuthenticate).');
        });
      }
      return response;
    });
  }
}


/// Will close the underlying `http.Client` depending on a constructor argument.
class AutoRefreshingClient extends DelegatingClient {
  final ClientId clientId;
  AccessCredentials credentials;
  Client authClient;

  AutoRefreshingClient(Client client, this.clientId, this.credentials,
                       {bool closeUnderlyingClient: false})
      : super(client, closeUnderlyingClient: closeUnderlyingClient) {
    assert (credentials.refreshToken != null);
    authClient = authenticatedClient(baseClient, credentials);
  }

  Future<StreamedResponse> send(BaseRequest request) {
    if (!credentials.accessToken.hasExpired) {
      // TODO: Can this return a "access token expired" message?
      // If so, we should handle it.
      return authClient.send(request);
    } else {
      return refreshCredentials(clientId, credentials, baseClient).then((cred) {
        credentials = cred;
        authClient = authenticatedClient(baseClient, cred);
        return authClient.send(request);
      });
    }
  }
}
