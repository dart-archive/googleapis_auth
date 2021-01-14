import 'dart:io';
import 'dart:convert';
import 'dart:async';

import 'package:http/http.dart';

import 'auth_http_utils.dart';
import '../auth_io.dart';

Future<AutoRefreshingAuthClient> fromApplicationsCredentialsFile(
  File file,
  String fileSource,
  List<String> scopes,
  Client baseClient,
) async {
  var credentials;
  try {
    credentials = json.decode(await file.readAsString());
  } on IOException {
    throw Exception(
      'Failed to read credentials file from $fileSource',
    );
  } on FormatException {
    throw Exception(
      'Failed to parse JSON from credentials file from $fileSource',
    );
  }

  if (credentials is Map && credentials['type'] == 'authorized_user') {
    final clientId = ClientId(
      credentials['client_id'],
      credentials['client_secret'],
    );
    return AutoRefreshingClient(
      baseClient,
      clientId,
      await refreshCredentials(
        clientId,
        AccessCredentials(
          // Hack: Create empty credentials that have expired.
          AccessToken('Bearer', '', DateTime(0).toUtc()),
          credentials['refresh_token'],
          scopes,
        ),
        baseClient,
      ),
      quotaProject: credentials['quota_project_id'],
    );
  }
  return await clientViaServiceAccount(
    ServiceAccountCredentials.fromJson(credentials),
    scopes,
    baseClient: baseClient,
  );
}
