import 'dart:async';
import 'dart:convert';

import 'package:googleapis_auth/auth.dart';
import 'package:googleapis_auth/src/utils.dart';
import 'package:http_base/http_base.dart';
import 'package:unittest/unittest.dart';

import 'test_utils.dart';


main() {
  test('access-token', () {
    var expiry = new DateTime.now().subtract(const Duration(seconds: 1));
    var expiryUtc = expiry.toUtc();

    expect(() => new AccessToken(null, 'bar', expiryUtc), throwsArgumentError);
    expect(() => new AccessToken('foo', null, expiryUtc), throwsArgumentError);
    expect(() => new AccessToken('foo', 'bar', null), throwsArgumentError);
    expect(() => new AccessToken('foo', 'bar', expiry), throwsArgumentError);

    var token = new AccessToken('foo', 'bar', expiryUtc);
    expect(token.type, equals('foo'));
    expect(token.data, equals('bar'));
    expect(token.expiry, equals(expiryUtc));
    expect(token.hasExpired, isTrue);

    var nonExpiredToken = new AccessToken(
        'foo', 'bar', expiryUtc.add(const Duration(days: 1)));
    expect(nonExpiredToken.hasExpired, isFalse);
  });

  test('access-credentials', () {
    var expiry = new DateTime.now().add(const Duration(days: 1)).toUtc();
    var aToken = new AccessToken('foo', 'bar', expiry);

    expect(() => new AccessCredentials(null, 'refresh', ['scope']),
           throwsArgumentError);
    expect(() => new AccessCredentials(aToken, 'refresh', null),
           throwsArgumentError);

    var credentials = new AccessCredentials(aToken, 'refresh', ['scope']);
    expect(credentials.accessToken, equals(aToken));
    expect(credentials.refreshToken, equals('refresh'));
    expect(credentials.scopes, equals(['scope']));
  });

  test('client-id', () {
    expect(() => new ClientId(null, 'secret'), throwsArgumentError);
    expect(() => new ClientId.serviceAccount(null), throwsArgumentError);

    var clientId = new ClientId('id', 'secret');
    expect(clientId.identifier, equals('id'));
    expect(clientId.secret, equals('secret'));
  });

  test('service-account-credentials', () {
    var clientId = new ClientId.serviceAccount('id');

    expect(() => new ServiceAccountCredentials(
        null, clientId, TestPrivateKeyString), throwsArgumentError);
    expect(() => new ServiceAccountCredentials('email', null,
        TestPrivateKeyString), throwsArgumentError);
    expect(() => new ServiceAccountCredentials('email', clientId, null),
            throwsArgumentError);

    var credentials =
        new ServiceAccountCredentials('email', clientId, TestPrivateKeyString);
    expect(credentials.email, equals('email'));
    expect(credentials.clientId, equals(clientId));
    expect(credentials.privateKey, equals(TestPrivateKeyString));

    var credentialsFromJson = new ServiceAccountCredentials.fromJson(
        JSON.encode({
        "private_key_id": "301029",
        "private_key": TestPrivateKeyString,
        "client_email": "a@b.com",
        "client_id": "myid",
        "type": "service_account"
    }));
    expect(credentialsFromJson.email, equals('a@b.com'));
    expect(credentialsFromJson.clientId.identifier, equals('myid'));
    expect(credentialsFromJson.clientId.secret, isNull);
    expect(credentialsFromJson.privateKey, equals(TestPrivateKeyString));
  });

  group('client-wrappers', () {
    var clientId = new ClientId('id', 'secret');
    var tomorrow = new DateTime.now().add(const Duration(days: 1)).toUtc();
    var yesterday =
        new DateTime.now().subtract(const Duration(days: 1)).toUtc();
    var aToken = new AccessToken('Bearer', 'bar', tomorrow);
    var credentials = new AccessCredentials(aToken, 'refresh', ['s1', 's2']);

    Future successfulRefresh(request) {
      expect(request.method, equals('POST'));
      expect('${request.url}',
             equals('https://accounts.google.com/o/oauth2/token'));

      return request.read().transform(ASCII.decoder).join('')
          .then(expectAsync((String result) {
        expect(result, equals('client_id=id&'
                              'client_secret=secret&'
                              'refresh_token=refresh&'
                              'grant_type=refresh_token'));
        var body = new StreamController()..add(ASCII.encode(JSON.encode({
            'token_type' : 'Bearer',
            'access_token' : 'atoken',
            'expires_in' : 3600,
        })))..close();

        return new Future.value(new ResponseImpl(
            200, headers: _JsonContentType, body: body.stream));
      }));
    }

    Future refreshErrorResponse(request) {
      return request.read().transform(ASCII.decoder).join('')
          .then(expectAsync((String result) {
        var body = new StreamController()..add(ASCII.encode(JSON.encode({
            'error' : 'An error occured'
        })))..close();

        return new Future.value(new ResponseImpl(
            400, headers: _JsonContentType, body: body.stream));
      }));
    }

    Future serverError(request) {
      return new Future.error(new Exception('transport layer exception'));
    }

    test('refreshCredentials-successfull', () {
      refreshCredentials(clientId, credentials, expectAsync(successfulRefresh))
          .then(expectAsync((newCredentials) {
        var expectedResultUtc = new DateTime.now().toUtc().add(
            const Duration(seconds: 3600 - MAX_EXPECTED_TIMEDIFF_IN_SECONDS));

        var accessToken = newCredentials.accessToken;
        expect(accessToken.type, equals('Bearer'));
        expect(accessToken.data, equals('atoken'));
        expect(accessToken.expiry.difference(expectedResultUtc).inSeconds,
               equals(0));

        expect(newCredentials.refreshToken, equals('refresh'));
        expect(newCredentials.scopes, equals(['s1', 's2']));
      }));
    });

    test('refreshCredentials-http-error', () {
      refreshCredentials(clientId, credentials, serverError)
          .catchError(expectAsync((error) {
        expect(error.toString(),
               equals('Exception: transport layer exception'));
      }));
    });

    test('refreshCredentials-error-response', () {
      refreshCredentials(clientId, credentials, refreshErrorResponse)
          .catchError(expectAsync((error) {
        expect(error is RefreshFailedException, isTrue);
      }));
    });

    group('authenticatedClient', () {
      var url = Uri.parse('http://www.example.com');

      test('successfull', () {
        var client = authenticatedClient(expectAsync((request) {
          expect(request.method, equals('POST'));
          expect(request.url, equals(url));
          expect(request.headers.names.length, equals(1));
          expect(request.headers['Authorization'], equals('Bearer bar'));

          return new Future.value(new ResponseImpl(204));
        }), credentials);

        client(new RequestImpl('POST', url)).then(expectAsync((response) {
          expect(response.statusCode, equals(204));
        }));
      });

      test('access-denied', () {
        var client = authenticatedClient(expectAsync((request) {
          expect(request.method, equals('POST'));
          expect(request.url, equals(url));
          expect(request.headers.names.length, equals(1));
          expect(request.headers['Authorization'], equals('Bearer bar'));

          var headers = new HeadersImpl({'www-authenticate' : 'foobar'});
          return new Future.value(new ResponseImpl(401, headers: headers));
        }), credentials);

        expect(client(new RequestImpl('POST', url)),
               throwsA(isAccessDeniedException));
      });

      test('non-bearer-token', () {
        var aToken = credentials.accessToken;
        var nonBearerCredentials = new AccessCredentials(
            new AccessToken('foobar', aToken.data, aToken.expiry),
            'refresh', ['s1', 's2']);

        expect(() => authenticatedClient((_) {}, nonBearerCredentials),
               throwsA(isArgumentError));
      });
    });

    group('autoRefreshingClient', () {
      var url = Uri.parse('http://www.example.com');

      test('up-to-date', () {
        var client = autoRefreshingClient(clientId, credentials,
            expectAsync((request) {
          return new Future.value(new ResponseImpl(200));
        }));

        client(new RequestImpl('POST', url)).then(expectAsync((response) {
          expect(response.statusCode, equals(200));
        }));
      });

      test('no-refresh-token', () {
        var credentials = new AccessCredentials(
            new AccessToken('Bearer', 'bar', yesterday), null, ['s1', 's2']);

        expect(() => autoRefreshingClient(clientId, credentials, (_) {}),
               throwsA(isArgumentError));
      });

      test('refresh-failed', () {
        var credentials = new AccessCredentials(new AccessToken(
            'Bearer', 'bar', yesterday), 'refresh', ['s1', 's2']);

        var client = autoRefreshingClient(clientId, credentials,
            expectAsync((request) {
          // This should be a refresh request.
          expect(request.headers['foo'], isNull);
          return refreshErrorResponse(request);
        }));

        var headers = new HeadersImpl({'foo' : 'bar'});

        expect(client(new RequestImpl('POST', url, headers: headers)),
               throwsA(isRefreshFailedException));
      });

      test('invalid-content-type', () {
        var credentials = new AccessCredentials(new AccessToken(
            'Bearer', 'bar', yesterday), 'refresh', ['s1', 's2']);

        var client = autoRefreshingClient(clientId, credentials,
            expectAsync((request) {
          // This should be a refresh request.
          expect(request.headers['foo'], isNull);
          return request.read().drain().then((_) {
            var body = new Stream.fromIterable([]);
            var headers = new HeadersImpl({'content-type' : 'foobar'});

            return new Future.value(
                new ResponseImpl(200, headers: headers, body: body));
          });
        }));

        var headers = new HeadersImpl({'foo' : 'bar'});

        expect(client(new RequestImpl('POST', url, headers: headers)),
               throwsA(isException));
      });

      test('successful-refresh', () {
        int serverInvocation = 0;

        var credentials = new AccessCredentials(
            new AccessToken('Bearer', 'bar', yesterday), 'refresh', ['s1']);

        var client = autoRefreshingClient(clientId, credentials,
            expectAsync((request) {
          if (serverInvocation++ == 0) {
            // This should be a refresh request.
            expect(request.headers['foo'], isNull);
            return successfulRefresh(request);
          } else {
            // This is the real request.
            expect(request.headers['foo'], equals('bar'));
            return new Future.value(new ResponseImpl(200));
          }
        }, count: 2));

        var headers = new HeadersImpl({'foo' : 'bar'});
        client(new RequestImpl('POST', url, headers: headers))
            .then(expectAsync((response) {
          expect(response.statusCode, equals(200));
        }));
      });
    });
  });
}

final _JsonContentType = new HeadersImpl({'content-type' : 'application/json'});