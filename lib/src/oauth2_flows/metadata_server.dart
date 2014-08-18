library googleapis_auth.metadata_server_flow;

import 'dart:async';
import 'dart:convert';

import 'package:http_base/http_base.dart' as http;
import '../utils.dart';
import '../../auth.dart';

/// Obtains access credentials form the metadata server.
///
/// Using this class assumes that the current program is running a
/// ComputeEngine VM. It will retrieve the current access token from the
/// metadata server.
class MetadataServerAuthorizationFlow {
  static const _SERVICE_ACCOUNT_URL_PREFIX =
      'http://metadata/computeMetadata/v1/instance/service-accounts';

  static final http.HeadersImpl _HEADERS = new http.HeadersImpl(const {
      'X-Google-Metadata-Request' : const ['True'],
  });

  final String email;
  final Uri _scopesUrl;
  final Uri _tokenUrl;
  final http.RequestHandler _client;

  factory MetadataServerAuthorizationFlow(
      http.RequestHandler client, {String email: 'default'}) {
    var encodedEmail = Uri.encodeComponent(email);
    var scopesUrl = Uri.parse(
        '$_SERVICE_ACCOUNT_URL_PREFIX/$encodedEmail/scopes');
    var tokenUrl = Uri.parse(
        '$_SERVICE_ACCOUNT_URL_PREFIX/$encodedEmail/token');
    return new MetadataServerAuthorizationFlow._(
        client, email, scopesUrl, tokenUrl);
  }

  MetadataServerAuthorizationFlow._(
      this._client, this.email, this._scopesUrl, this._tokenUrl);

  Future<AccessCredentials> run() {
    return Future.wait([_getToken(), _getScopes()]).then((List results) {
      var json = results[0];
      var scopes = results[1]
          .replaceAll('\n', ' ')
          .split(' ')
          .where((part) => part.length > 0)
          .toList();

      var type = json['token_type'];
      var accessToken = json['access_token'];
      var expiresIn = json['expires_in'];
      var error = json['error'];

      if (error != null) {
        throw new Exception('Error while obtaining credentials from metadata '
            'server. Error message: $error.');
      }

      if (type != 'Bearer' || accessToken == null || expiresIn is! int) {
        throw new Exception('Invalid response from metadata server.');
      }

      return new AccessCredentials(
          new AccessToken(type, accessToken, expiryDate(expiresIn)),
          null,
          scopes);
    });
  }

  Future<Map> _getToken() {
    var tokenRequest =
        new http.RequestImpl('GET', _tokenUrl, headers: _HEADERS);
    return _client(tokenRequest).then((response) {
      return response.read()
          .transform(UTF8.decoder).transform(JSON.decoder).first;
    });
  }

  Future<String> _getScopes() {
    var scopesRequest =
        new http.RequestImpl('GET', _scopesUrl, headers: _HEADERS);
    return _client(scopesRequest).then((response) {
      return response.read().transform(UTF8.decoder).join('');
    });
  }
}
