library googleapis_auth.metadata_server;

import 'dart:async';
import 'dart:convert';

import 'package:googleapis_auth/oauth2.dart';
import 'package:googleapis_auth/src/oauth2_flows/metadata_server.dart';
import 'package:http_base/http_base.dart';
import 'package:unittest/unittest.dart';

import '../test_utils.dart';

main() {
  var apiUrl = 'http://metadata/computeMetadata/v1';
  var tokenUrl = '$apiUrl/instance/service-accounts/default/token';
  var scopesUrl = '$apiUrl/instance/service-accounts/default/scopes';

  Future<Response> successfullAccessToken(Request request) {
    expect(request.method, equals('GET'));
    expect(request.url.toString(), equals(tokenUrl));

    var body = (new StreamController()..add(UTF8.encode(JSON.encode({
      'access_token' : 'atok',
      'expires_in' : 3600,
      'token_type' : 'Bearer',
    })))..close()).stream;
    return new Future.value(new ResponseImpl(200, body: body));
  }

  Future<Response> invalidAccessToken(Request request) {
    expect(request.method, equals('GET'));
    expect(request.url.toString(), equals(tokenUrl));

    var body = (new StreamController()..add(UTF8.encode(JSON.encode({
      // Missing 'expires_in' entry
      'access_token' : 'atok',
      'token_type' : 'Bearer',
    })))..close()).stream;
    return new Future.value(new ResponseImpl(200, body: body));
  }

  Future<Response> successfullScopes(Request request) {
    expect(request.method, equals('GET'));
    expect(request.url.toString(), equals(scopesUrl));

    var body = (new StreamController()
        ..add(UTF8.encode('s1\ns2'))
        ..close()).stream;
    return new Future.value(new ResponseImpl(200, body: body));
  }

  group('metadata-server-authorization-flow', () {
    test('successfull', () {
      int requestNr = 0;
      var flow = new MetadataServerAuthorizationFlow(expectAsync((request) {
        var url = request.url.toString();
        if (url == tokenUrl) {
          return successfullAccessToken(request);
        } else if (url == scopesUrl) {
          return successfullScopes(request);
        } else {
          fail("Invalid URL $url (expected: $tokenUrl or $scopesUrl).");
        }
      }, count: 2));

      flow.run().then(expectAsync((AccessCredentials credentials) {
        expect(credentials.accessToken.data, equals('atok'));
        expect(credentials.accessToken.type, equals('Bearer'));
        expect(credentials.scopes, equals(['s1', 's2']));

        var now = new DateTime.now().toUtc();
        expectExpiryOneHourFromNow(credentials.accessToken);
      }));
    });

    test('invalid-server-reponse', () {
      int requestNr = 0;
      var flow = new MetadataServerAuthorizationFlow(expectAsync((request) {
        if (requestNr++ == 0) return invalidAccessToken(request);
        else return successfullScopes(request);
      }, count: 2));
      expect(flow.run(), throwsA(isException));
    });


    test('token-transport-error', () {
      int requestNr = 0;
      var flow = new MetadataServerAuthorizationFlow(expectAsync((request) {
        if (requestNr++ == 0) return transportFailure(request);
        else return successfullScopes(request);
      }, count: 2));
      expect(flow.run(), throwsA(isTransportException));
    });

    test('scopes-transport-error', () {
      int requestNr = 0;
      var flow = new MetadataServerAuthorizationFlow(expectAsync((request) {
        if (requestNr++ == 0) return successfullAccessToken(request);
        else return transportFailure(request);
      }, count: 2));
      expect(flow.run(), throwsA(isTransportException));
    });
  });
}
