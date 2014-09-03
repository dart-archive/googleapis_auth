library googleapis_auth.auth;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart';

import 'src/auth_http_utils.dart';
import 'src/crypto/pem.dart';
import 'src/crypto/rsa.dart';
import 'src/http_client_base.dart';
import 'src/utils.dart';


/// Represents an oauth2 access token.
class AccessToken {
  /// The token type, usually "Bearer"
  final String type;

  /// The access token data.
  final String data;

  /// Time at which the token will be expired (UTC time)
  final DateTime expiry;

  /// [expiry] must be a UTC `DateTime`.
  AccessToken(String this.type, String this.data, DateTime this.expiry) {
    if (type == null || data == null || expiry == null) {
      throw new ArgumentError('Arguments type/data/expiry may not be null.');
    }

    if (!expiry.isUtc) {
      throw new ArgumentError('The expiry date must be a Utc DateTime.');
    }
  }

  bool get hasExpired {
    return new DateTime.now().toUtc().isAfter(expiry);
  }

  String toString() => "AccessToken(type=$type, data=$data, expiry=$expiry)";
}


/// Represents oauth2 credentials
class AccessCredentials {
  /// An access token.
  final AccessToken accessToken;

  /// A refresh token.
  final String refreshToken;

  /// Scopes these credentials are valid for.
  final List<String> scopes;

  AccessCredentials(this.accessToken, this.refreshToken, this.scopes) {
    if (accessToken == null || scopes == null) {
      throw new ArgumentError('Arguments accessToken/scopes must not be null.');
    }
  }
}


/// Represents the client application's credentials.
class ClientId {
  /// The identifier used to identify this application to the server.
  final String identifier;

  /// The client secret used to identify this application to the server.
  final String secret;

  ClientId(this.identifier, this.secret) {
    if (identifier == null) {
      throw new ArgumentError('Argument identifier may not be null.');
    }
  }

  ClientId.serviceAccount(this.identifier) : secret = null {
    if (identifier == null) {
      throw new ArgumentError('Argument identifier may not be null.');
    }
  }
}


/// Represents credentials for a service account.
class ServiceAccountCredentials {
  /// The email addres of this service account
  final String email;

  /// The clientId
  final ClientId clientId;

  /// Private key
  final String privateKey;

  /// Private key as an [RSAPrivateKey].
  final RSAPrivateKey privateRSAKey;

  factory ServiceAccountCredentials.fromJson(String string) {
    var json = JSON.decode(string);
    var identifier = json['client_id'];
    var privateKey = json['private_key'];
    var email = json['client_email'];
    var type = json['type'];

    if (type != 'service_account') {
      throw new ArgumentError('The given credentials are not of type '
          'service_account (was: $type).');
    }

    if (identifier == null || privateKey == null || email == null) {
      throw new ArgumentError('The given credentials do not contain a'
          'identifier, privateKey or email field.');
    }

    var clientId = new ClientId(identifier, null);
    return new ServiceAccountCredentials(email, clientId, privateKey);
  }

  ServiceAccountCredentials(this.email, this.clientId, String privateKey)
      : privateKey = privateKey,
        privateRSAKey = keyFromString(privateKey) {
    if (email == null || clientId == null || privateKey == null) {
      throw new ArgumentError(
          'Arguments email/clientId/privateKey must not be null.');
    }
  }
}


/// A authenticated HTTP client.
abstract class AuthClient implements Client {
  /// The credentials currently used for making HTTP requests.
  AccessCredentials get credentials;
}


/// A autorefreshing, authenticated HTTP client.
abstract class AutoRefreshingAuthClient implements AuthClient {
  /// A broadcast stream of [AccessCredentials].
  ///
  /// A listener will get notified when new [AccessCredentials] were obtained.
  Stream<AccessCredentials> get credentialUpdates;
}


/// Thrown if an attempt to refresh a token failed.
class RefreshFailedException implements Exception {
  final String message;
  RefreshFailedException(this.message);
  String toString() => message;
}


/// Thrown if an attempt to make an authorized request failed.
class AccessDeniedException implements Exception {
  final String message;
  AccessDeniedException(this.message);
  String toString() => message;
}


/// Thrown if user did not give his consent.
class UserConsentException implements Exception {
  final String message;
  UserConsentException(this.message);
  String toString() => message;
}


/// Obtain an `http.Client` which automatically authenticates
/// requests using [credentials].
///
/// Note that the returned `RequestHandler` will not auto-refresh the given
/// [credentials].
///
/// The user is responsible for closing the returned HTTP [Client].
/// Closing the returned [Client] will not close [baseClient].
AuthClient authenticatedClient(Client baseClient,
                               AccessCredentials credentials) {
  if (credentials.accessToken.type != 'Bearer') {
    throw new ArgumentError('Only Bearer access tokens are accepted.');
  }
  return new AuthenticatedClient(baseClient, credentials);
}


/// Obtain an `http.Client` which automatically refreshes [credentials]
/// before they expire. Uses [baseClient] as a base for making authenticated
/// http requests and for refreshing [credentials].
///
/// The user is responsible for closing the returned HTTP [Client].
/// Closing the returned [Client] will not close [baseClient].
AutoRefreshingAuthClient autoRefreshingClient(ClientId clientId,
                                              AccessCredentials credentials,
                                              Client baseClient) {
  if (credentials.refreshToken == null) {
    throw new ArgumentError('Refresh token in AccessCredentials was `null`.');
  }
  return new AutoRefreshingClient(baseClient, clientId, credentials);
}


/// Tries to obtain refreshed [AccessCredentials] based on [credentials] using
/// [client].
Future<AccessCredentials> refreshCredentials(ClientId clientId,
                                             AccessCredentials credentials,
                                             Client client) {
  var formValues = [
      'client_id=${Uri.encodeComponent(clientId.identifier)}',
      'client_secret=${Uri.encodeComponent(clientId.secret)}',
      'refresh_token=${Uri.encodeComponent(credentials.refreshToken)}',
      'grant_type=refresh_token',
  ];

  var body = new Stream.fromIterable([(ASCII.encode(formValues.join('&')))]);
  var request = new RequestImpl('POST', _GoogleTokenUri, body);
  request.headers['content-type'] = 'application/x-www-form-urlencoded';

  return client.send(request).then((response) {
    var contentType = response.headers['content-type'];
    contentType = contentType == null ? null : contentType.toLowerCase();

    if (contentType == null ||
        (!contentType.contains('json') &&
         !contentType.contains('javascript'))) {
      return response.stream.drain().catchError((_) {}).then((_) {
        throw new Exception(
            'Server responded with invalid content type: $contentType. '
            'Expected json response.');
      });
    }

    return response.stream
        .transform(ASCII.decoder)
        .transform(JSON.decoder).first.then((Map json) {

      var token = json['access_token'];
      var seconds = json['expires_in'];
      var tokenType = json['token_type'];
      var error = json['error'];

      if (response.statusCode != 200 && error != null) {
        throw new RefreshFailedException('Refreshing attempt failed. '
            'Response was ${response.statusCode}. Error message was $error.');
      }

      if (token == null || seconds is! int || tokenType != 'Bearer') {
        throw new Exception('Refresing attempt failed. '
            'Invalid server response.');
      }

      return new AccessCredentials(
          new AccessToken(tokenType, token, expiryDate(seconds)),
          credentials.refreshToken,
          credentials.scopes);
    });
  });
}


final _GoogleTokenUri = Uri.parse('https://accounts.google.com/o/oauth2/token');
