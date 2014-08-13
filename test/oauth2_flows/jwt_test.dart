library googleapis_auth.jwt_test;

import 'dart:async';
import 'dart:convert';

import 'package:googleapis_auth/oauth2.dart';
import 'package:googleapis_auth/src/oauth2_flows/jwt.dart';
import 'package:http_base/http_base.dart';
import 'package:unittest/unittest.dart';

import '../test_utils.dart';

main() {
  var tokenUrl = 'https://accounts.google.com/o/oauth2/token';

  Future<Response> successfullSignRequest(Request request) {
    expect(request.method, equals('POST'));
    expect(request.url.toString(), equals(tokenUrl));

    return request.read().transform(UTF8.decoder)
        .join('').then(expectAsync((String urlEncoded) {
      // We are not asserting what comes after '&assertion=' because this is
      // time dependend.
      expect(urlEncoded, startsWith(
          'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer'
          '&assertion='));
      var body = (new StreamController()..add(UTF8.encode(JSON.encode({
        'access_token' : 'atok',
        'expires_in' : 3600,
        'token_type' : 'Bearer',
      })))..close()).stream;
      return new Future.value(new ResponseImpl(200, body: body));

    }));
  }

  Future<Response> invalidAccessToken(Request request) {
    var body = (new StreamController()..add(UTF8.encode(JSON.encode({
      // Missing 'expires_in' entry
      'access_token' : 'atok',
      'token_type' : 'Bearer',
    })))..close()).stream;
    return new Future.value(new ResponseImpl(200, body: body));
  }

  group('jwt-flow', () {
    var clientEmail = 'a@b.com';
    var scopes = ['s1', 's2'];

    test('successfull', () {
      var flow = new JwtFlow(clientEmail, TestPrivateKey, scopes,
          (expectAsync(successfullSignRequest)));

      flow.run().then(expectAsync((AccessCredentials credentials) {
        expect(credentials.accessToken.data, equals('atok'));
        expect(credentials.accessToken.type, equals('Bearer'));
        expect(credentials.scopes, equals(['s1', 's2']));
        expectExpiryOneHourFromNow(credentials.accessToken);
      }));
    });

    test('invalid-server-response', () {
      var flow = new JwtFlow(clientEmail, TestPrivateKey, scopes,
          (expectAsync(invalidAccessToken)));

      expect(flow.run(), throwsA(isException));
    });

    test('transport-failure', () {
      var flow = new JwtFlow(clientEmail, TestPrivateKey, scopes,
          (expectAsync(transportFailure)));

      expect(flow.run(), throwsA(isTransportException));
    });
  });
}
