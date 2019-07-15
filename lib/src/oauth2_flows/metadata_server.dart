// Copyright (c) 2014, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library googleapis_auth.metadata_server_flow;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import '../../auth.dart';
import '../utils.dart';

/// Obtains access credentials form the metadata server.
///
/// Using this class assumes that the current program is running a
/// ComputeEngine VM. It will retrieve the current access token from the
/// metadata server, looking first for one set in the environment under
/// `$GCE_METADATA_HOST`.
class MetadataServerAuthorizationFlow {
  static const _HEADERS = const {'Metadata-Flavor': 'Google'};
  static const _SERVICE_ACCOUNT_URL_INFIX =
      'computeMetadata/v1/instance/service-accounts';
  static const _DEFAULT_METADATA_HOST = "metadata";
  static const _GCE_METADATA_HOST_ENV_VAR = "GCE_METADATA_HOST";

  final String email;
  final Uri _scopesUrl;
  final Uri _tokenUrl;
  final http.Client _client;

  factory MetadataServerAuthorizationFlow(http.Client client,
      {String email: 'default'}) {
    var encodedEmail = Uri.encodeComponent(email);

    final metadataHost = Platform.environment[_GCE_METADATA_HOST_ENV_VAR] ??
        _DEFAULT_METADATA_HOST;
    final serviceAccountPrefix =
        "http://$metadataHost/$_SERVICE_ACCOUNT_URL_INFIX";

    var scopesUrl = Uri.parse('$serviceAccountPrefix/$encodedEmail/scopes');
    var tokenUrl = Uri.parse('$serviceAccountPrefix/$encodedEmail/token');
    return new MetadataServerAuthorizationFlow._(
        client, email, scopesUrl, tokenUrl);
  }

  MetadataServerAuthorizationFlow._(
      this._client, this.email, this._scopesUrl, this._tokenUrl);

  Future<AccessCredentials> run() async {
    final results = await Future.wait([_getToken(), _getScopes()]);
    final Map token = results.first;
    final String scopesString = results.last;

    var json = token;
    var scopes = scopesString
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
  }

  Future<Map> _getToken() async {
    var response = await _client.get(_tokenUrl, headers: _HEADERS);
    return jsonDecode(response.body);
  }

  Future<String> _getScopes() async {
    var response = await _client.get(_scopesUrl, headers: _HEADERS);
    return response.body;
  }
}
