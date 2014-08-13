library googleapis_auth.auth_code_test;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:googleapis_auth/oauth2.dart';
import 'package:googleapis_auth/src/oauth2_flows/auth_code.dart';
import 'package:http_base/http_base.dart';
import 'package:unittest/unittest.dart';

import '../test_utils.dart';

main() {
  var clientId = new ClientId('id', 'secret');
  var scopes = ['s1', 's2'];

  // Validation + Responses from the authorization server.

  Function successFullResponse({bool manual}) {
    return (Request request) {
      expect(request.method, equals('POST'));
      expect('${request.url}',
             equals('https://accounts.google.com/o/oauth2/token'));
      expect(request.headers['content-type'],
             equals('application/x-www-form-urlencoded'));

      return request.read()
          .transform(UTF8.decoder).join('').then((requestBody) {
        var pairs = requestBody.split('&');
        expect(pairs, hasLength(5));
        expect(pairs[0], equals('grant_type=authorization_code'));
        expect(pairs[1], equals('code=mycode'));
        expect(pairs[3], equals('client_id=id'));
        expect(pairs[4], equals('client_secret=secret'));
        if (manual) {
          expect(pairs[2],
                 equals('redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob'));
        } else {
          expect(pairs[2], startsWith('redirect_uri='));

          var url = Uri.parse(Uri.decodeComponent(
              pairs[2].substring('redirect_uri='.length)));
          expect(url.scheme, equals('http'));
          expect(url.host, equals('localhost'));
        }

        var result = {
            'token_type' : 'Bearer',
            'access_token' : 'tokendata',
            'expires_in' : 3600,
            'refresh_token' : 'my-refresh-token',
        };
        var body = new Stream.fromIterable([ASCII.encode(JSON.encode(result))]);

        return new ResponseImpl(200, body: body);
      });
    };
  }

  Future<Response> invalidResponse(Request request) {
    return request.read().transform(UTF8.decoder).join('').then((requestBody) {
      // Missing expires_in field!
      var result = {
          'token_type' : 'Bearer',
          'access_token' : 'tokendata',
          'refresh_token' : 'my-refresh-token',
      };
      var body = new Stream.fromIterable([ASCII.encode(JSON.encode(result))]);

      return new ResponseImpl(200, body: body);
    });
  }


  // Validation functions for user prompt and access credentials.

  void validateAccessCredentials(AccessCredentials credentials) {
    expect(credentials.accessToken.data, equals('tokendata'));
    expect(credentials.accessToken.type, equals('Bearer'));
    expect(credentials.scopes, equals(['s1', 's2']));
    expect(credentials.refreshToken, equals('my-refresh-token'));
    expectExpiryOneHourFromNow(credentials.accessToken);
  }

  Uri validateUserPromptUri(String url, {bool manual: false}) {
    var uri = Uri.parse(url);
    expect(uri.scheme, equals('https'));
    expect(uri.host, equals('accounts.google.com'));
    expect(uri.path, equals('/o/oauth2/auth'));
    expect(uri.queryParameters['client_id'], equals(clientId.identifier));
    expect(uri.queryParameters['response_type'], equals('code'));
    expect(uri.queryParameters['scope'], equals('s1 s2'));
    expect(uri.queryParameters['redirect_uri'], isNotNull);

    var redirectUri = Uri.parse(uri.queryParameters['redirect_uri']);

    if (manual) {
      expect('$redirectUri', equals('urn:ietf:wg:oauth:2.0:oob'));
    } else {
      expect(uri.queryParameters['state'], isNotNull);
      expect(redirectUri.scheme, equals('http'));
      expect(redirectUri.host, equals('localhost'));
    }

    return redirectUri;
  }


  group('authorization-code-flow', () {
    group('manual-copy-paste', () {
      Future<String> manualUserPrompt(String url) {
        validateUserPromptUri(url, manual: true);
        return new Future.value('mycode');
      }

      test('successfull', () {
        var flow = new AuthorizationCodeGrantManualFlow(
            clientId,
            scopes,
            successFullResponse(manual: true),
            manualUserPrompt);
        flow.run().then(expectAsync(validateAccessCredentials));
      });

      test('user-exception', () {
        // We use a TransportException here for convenience.
        Future<String> manualUserPromptError(String url) {
          return new Future.error(new TransportException());
        }
        var flow = new AuthorizationCodeGrantManualFlow(
            clientId,
            scopes,
            successFullResponse(manual: true),
            manualUserPromptError);
        expect(flow.run(), throwsA(isTransportException));
      });

      test('transport-exception', () {
        var flow = new AuthorizationCodeGrantManualFlow(
            clientId, scopes, transportFailure, manualUserPrompt);
        expect(flow.run(), throwsA(isTransportException));
      });

      test('invalid-server-response', () {
        var flow = new AuthorizationCodeGrantManualFlow(
            clientId, scopes, invalidResponse, manualUserPrompt);
        expect(flow.run(), throwsA(isException));
      });
    });

    group('http-server', () {
      void callRedirectionEndpoint(Uri authCodeCall) {
        var ioClient = new HttpClient();
        ioClient.getUrl(authCodeCall)
            .then((request) => request.close())
            .then((response) => response.drain())
            .whenComplete(expectAsync(() { ioClient.close(); }));
      }

      void userPrompt(String url) {
        var redirectUri = validateUserPromptUri(url);
        var authCodeCall = new Uri(
            scheme: redirectUri.scheme,
            host: redirectUri.host,
            port: redirectUri.port,
            path: redirectUri.path,
            queryParameters: {
              'state' : Uri.parse(url).queryParameters['state'],
              'code' : 'mycode',
            });
        callRedirectionEndpoint(authCodeCall);
      }

      void userPromptInvalidAuthCodeCallback(String url) {
        var redirectUri = validateUserPromptUri(url);
        var authCodeCall = new Uri(
            scheme: redirectUri.scheme,
            host: redirectUri.host,
            port: redirectUri.port,
            path: redirectUri.path,
            queryParameters: {
              'state' : Uri.parse(url).queryParameters['state'],
              'error' : 'failed to authenticate',
            });
        callRedirectionEndpoint(authCodeCall);
      }

      test('successfull', () {
        var flow = new AuthorizationCodeGrantServerFlow(
            clientId,
            scopes,
            successFullResponse(manual: false),
            expectAsync(userPrompt));
        flow.run().then(expectAsync(validateAccessCredentials));
      });

      test('transport-exception', () {
        var flow = new AuthorizationCodeGrantServerFlow(
            clientId, scopes, transportFailure, expectAsync(userPrompt));
        expect(flow.run(), throwsA(isTransportException));
      });

      test('invalid-server-response', () {
        var flow = new AuthorizationCodeGrantServerFlow(
            clientId, scopes, invalidResponse, expectAsync(userPrompt));
        expect(flow.run(), throwsA(isException));
      });

      test('failed-authentication', () {
        var flow = new AuthorizationCodeGrantServerFlow(
            clientId,
            scopes,
            successFullResponse(manual: false),
            expectAsync(userPromptInvalidAuthCodeCallback));
        expect(flow.run(), throwsA(isUserConsentException));
      });
    });
  });
}
