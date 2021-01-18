// Copyright (c) 2014, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library googleapis_auth.oauth2_test;

import 'dart:async';
import 'dart:convert';

import 'package:googleapis_auth/auth.dart';
import 'package:googleapis_auth/src/utils.dart';
import 'package:googleapis_auth/src/http_client_base.dart';
import 'package:test/test.dart';
import 'package:http/http.dart';

import 'test_utils.dart';

final _defaultResponse = Response('', 500);
final _defaultResponseHandler = (Request _) async => _defaultResponse;

void main() {
  test('access-token', () {
    var expiry = DateTime.now().subtract(const Duration(seconds: 1));
    var expiryUtc = expiry.toUtc();

    expect(() => AccessToken('foo', 'bar', expiry), throwsArgumentError);

    var token = AccessToken('foo', 'bar', expiryUtc);
    expect(token.type, equals('foo'));
    expect(token.data, equals('bar'));
    expect(token.expiry, equals(expiryUtc));
    expect(token.hasExpired, isTrue);

    var nonExpiredToken =
        AccessToken('foo', 'bar', expiryUtc.add(const Duration(days: 1)));
    expect(nonExpiredToken.hasExpired, isFalse);
  });

  test('access-credentials', () {
    var expiry = DateTime.now().add(const Duration(days: 1)).toUtc();
    var aToken = AccessToken('foo', 'bar', expiry);

    var credentials = AccessCredentials(aToken, 'refresh', ['scope']);
    expect(credentials.accessToken, equals(aToken));
    expect(credentials.refreshToken, equals('refresh'));
    expect(credentials.scopes, equals(['scope']));
  });

  test('client-id', () {
    var clientId = ClientId('id', 'secret');
    expect(clientId.identifier, equals('id'));
    expect(clientId.secret, equals('secret'));
  });

  group('service-account-credentials', () {
    var clientId = ClientId.serviceAccount('id');

    var credentials = const {
      'private_key_id': '301029',
      'private_key': TestPrivateKeyString,
      'client_email': 'a@b.com',
      'client_id': 'myid',
      'type': 'service_account'
    };

    test('from-valid-individual-params', () {
      var credentials =
          ServiceAccountCredentials('email', clientId, TestPrivateKeyString);
      expect(credentials.email, equals('email'));
      expect(credentials.clientId, equals(clientId));
      expect(credentials.privateKey, equals(TestPrivateKeyString));
      expect(credentials.impersonatedUser, isNull);
    });

    test('from-valid-individual-params-with-user', () {
      var credentials = ServiceAccountCredentials(
          'email', clientId, TestPrivateKeyString,
          impersonatedUser: 'x@y.com');
      expect(credentials.email, equals('email'));
      expect(credentials.clientId, equals(clientId));
      expect(credentials.privateKey, equals(TestPrivateKeyString));
      expect(credentials.impersonatedUser, equals('x@y.com'));
    });

    test('from-json-string', () {
      var credentialsFromJson =
          ServiceAccountCredentials.fromJson(jsonEncode(credentials));
      expect(credentialsFromJson.email, equals('a@b.com'));
      expect(credentialsFromJson.clientId.identifier, equals('myid'));
      expect(credentialsFromJson.clientId.secret, isNull);
      expect(credentialsFromJson.privateKey, equals(TestPrivateKeyString));
      expect(credentialsFromJson.impersonatedUser, isNull);
    });

    test('from-json-string-with-user', () {
      var credentialsFromJson = ServiceAccountCredentials.fromJson(
          jsonEncode(credentials),
          impersonatedUser: 'x@y.com');
      expect(credentialsFromJson.email, equals('a@b.com'));
      expect(credentialsFromJson.clientId.identifier, equals('myid'));
      expect(credentialsFromJson.clientId.secret, isNull);
      expect(credentialsFromJson.privateKey, equals(TestPrivateKeyString));
      expect(credentialsFromJson.impersonatedUser, equals('x@y.com'));
    });

    test('from-json-map', () {
      var credentialsFromJson = ServiceAccountCredentials.fromJson(credentials);
      expect(credentialsFromJson.email, equals('a@b.com'));
      expect(credentialsFromJson.clientId.identifier, equals('myid'));
      expect(credentialsFromJson.clientId.secret, isNull);
      expect(credentialsFromJson.privateKey, equals(TestPrivateKeyString));
      expect(credentialsFromJson.impersonatedUser, isNull);
    });

    test('from-json-map-with-user', () {
      var credentialsFromJson = ServiceAccountCredentials.fromJson(credentials,
          impersonatedUser: 'x@y.com');
      expect(credentialsFromJson.email, equals('a@b.com'));
      expect(credentialsFromJson.clientId.identifier, equals('myid'));
      expect(credentialsFromJson.clientId.secret, isNull);
      expect(credentialsFromJson.privateKey, equals(TestPrivateKeyString));
      expect(credentialsFromJson.impersonatedUser, equals('x@y.com'));
    });
  });

  group('client-wrappers', () {
    var clientId = ClientId('id', 'secret');
    var tomorrow = DateTime.now().add(const Duration(days: 1)).toUtc();
    var yesterday = DateTime.now().subtract(const Duration(days: 1)).toUtc();
    var aToken = AccessToken('Bearer', 'bar', tomorrow);
    var credentials = AccessCredentials(aToken, 'refresh', ['s1', 's2']);

    Future<Response> successfulRefresh(Request request) {
      expect(request.method, equals('POST'));
      expect('${request.url}',
          equals('https://accounts.google.com/o/oauth2/token'));
      expect(
          request.body,
          equals('client_id=id&'
              'client_secret=secret&'
              'refresh_token=refresh&'
              'grant_type=refresh_token'));
      var body = jsonEncode({
        'token_type': 'Bearer',
        'access_token': 'atoken',
        'expires_in': 3600,
      });

      return Future.value(Response(body, 200, headers: _jsonContentType));
    }

    Future<Response> refreshErrorResponse(Request request) {
      var body = jsonEncode({'error': 'An error occured'});
      return Future<Response>.value(
          Response(body, 400, headers: _jsonContentType));
    }

    Future<Response> serverError(Request request) {
      return Future<Response>.error(Exception('transport layer exception'));
    }

    test('refreshCredentials-successfull', () async {
      var newCredentials = await refreshCredentials(clientId, credentials,
          mockClient(expectAsync1(successfulRefresh), expectClose: false));
      var expectedResultUtc = DateTime.now().toUtc().add(
          const Duration(seconds: 3600 - MAX_EXPECTED_TIMEDIFF_IN_SECONDS));

      var accessToken = newCredentials.accessToken;
      expect(accessToken.type, equals('Bearer'));
      expect(accessToken.data, equals('atoken'));
      expect(accessToken.expiry.difference(expectedResultUtc).inSeconds,
          equals(0));

      expect(newCredentials.refreshToken, equals('refresh'));
      expect(newCredentials.scopes, equals(['s1', 's2']));
    });

    test('refreshCredentials-http-error', () async {
      try {
        await refreshCredentials(
            clientId, credentials, mockClient(serverError, expectClose: false));
        fail('expected error');
      } catch (error) {
        expect(
            error.toString(), equals('Exception: transport layer exception'));
      }
    });

    test('refreshCredentials-error-response', () async {
      try {
        await refreshCredentials(clientId, credentials,
            mockClient(refreshErrorResponse, expectClose: false));
        fail('expected error');
      } catch (error) {
        expect(error is RefreshFailedException, isTrue);
      }
    });

    group('authenticatedClient', () {
      var url = Uri.parse('http://www.example.com');

      test('successfull', () async {
        var client = authenticatedClient(
            mockClient(expectAsync1((request) {
              expect(request.method, equals('POST'));
              expect(request.url, equals(url));
              expect(request.headers.length, equals(1));
              expect(request.headers['Authorization'], equals('Bearer bar'));

              return Future.value(Response('', 204));
            }), expectClose: false),
            credentials);
        expect(client.credentials, equals(credentials));

        var response = await client.send(RequestImpl('POST', url));
        expect(response.statusCode, equals(204));
      });

      test('access-denied', () {
        var client = authenticatedClient(
            mockClient(expectAsync1((request) {
              expect(request.method, equals('POST'));
              expect(request.url, equals(url));
              expect(request.headers.length, equals(1));
              expect(request.headers['Authorization'], equals('Bearer bar'));

              var headers = const {'www-authenticate': 'foobar'};
              return Future.value(Response('', 401, headers: headers));
            }), expectClose: false),
            credentials);
        expect(client.credentials, equals(credentials));

        expect(client.send(RequestImpl('POST', url)),
            throwsA(isAccessDeniedException));
      });

      test('non-bearer-token', () {
        var aToken = credentials.accessToken;
        var nonBearerCredentials = AccessCredentials(
            AccessToken('foobar', aToken.data, aToken.expiry),
            'refresh',
            ['s1', 's2']);

        expect(
            () => authenticatedClient(
                mockClient(_defaultResponseHandler, expectClose: false),
                nonBearerCredentials),
            throwsA(isArgumentError));
      });
    });

    group('autoRefreshingClient', () {
      var url = Uri.parse('http://www.example.com');

      test('up-to-date', () async {
        var client = autoRefreshingClient(
            clientId,
            credentials,
            mockClient(expectAsync1((request) {
              return Future.value(Response('', 200));
            }), expectClose: false));
        expect(client.credentials, equals(credentials));

        var response = await client.send(RequestImpl('POST', url));
        expect(response.statusCode, equals(200));
      });

      test('no-refresh-token', () {
        var credentials = AccessCredentials(
            AccessToken('Bearer', 'bar', yesterday), null, ['s1', 's2']);

        expect(
            () => autoRefreshingClient(clientId, credentials,
                mockClient(_defaultResponseHandler, expectClose: false)),
            throwsA(isArgumentError));
      });

      test('refresh-failed', () {
        var credentials = AccessCredentials(
            AccessToken('Bearer', 'bar', yesterday), 'refresh', ['s1', 's2']);

        var client = autoRefreshingClient(
            clientId,
            credentials,
            mockClient(expectAsync1((request) {
              // This should be a refresh request.
              expect(request.headers['foo'], isNull);
              return refreshErrorResponse(request);
            }), expectClose: false));
        expect(client.credentials, equals(credentials));

        var request = RequestImpl('POST', url);
        request.headers.addAll({'foo': 'bar'});
        expect(client.send(request), throwsA(isRefreshFailedException));
      });

      test('invalid-content-type', () {
        var credentials = AccessCredentials(
            AccessToken('Bearer', 'bar', yesterday), 'refresh', ['s1', 's2']);

        var client = autoRefreshingClient(
            clientId,
            credentials,
            mockClient(expectAsync1((request) {
              // This should be a refresh request.
              expect(request.headers['foo'], isNull);
              var headers = {'content-type': 'image/png'};

              return Future.value(Response('', 200, headers: headers));
            }), expectClose: false));
        expect(client.credentials, equals(credentials));

        var request = RequestImpl('POST', url);
        request.headers.addAll({'foo': 'bar'});
        expect(client.send(request), throwsA(isException));
      });

      test('successful-refresh', () async {
        var serverInvocation = 0;

        var credentials = AccessCredentials(
            AccessToken('Bearer', 'bar', yesterday), 'refresh', ['s1']);

        var client = autoRefreshingClient(
            clientId,
            credentials,
            mockClient(
                expectAsync1((request) {
                  if (serverInvocation++ == 0) {
                    // This should be a refresh request.
                    expect(request.headers['foo'], isNull);
                    return successfulRefresh(request);
                  } else {
                    // This is the real request.
                    expect(request.headers['foo'], equals('bar'));
                    return Future.value(Response('', 200));
                  }
                }, count: 2),
                expectClose: false));
        expect(client.credentials, equals(credentials));

        var executed = false;
        client.credentialUpdates.listen(expectAsync1((newCredentials) {
          expect(newCredentials.accessToken.type, equals('Bearer'));
          expect(newCredentials.accessToken.data, equals('atoken'));
          executed = true;
        }), onDone: expectAsync0(() {}));

        var request = RequestImpl('POST', url);
        request.headers.addAll({'foo': 'bar'});

        var response = await client.send(request);
        expect(response.statusCode, equals(200));

        // The `client.send()` will have triggered a credentials refresh.
        expect(executed, isTrue);

        client.close();
      });
    });
  });
}

final _jsonContentType = const {'content-type': 'application/json'};
