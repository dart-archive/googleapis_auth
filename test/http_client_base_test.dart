library googleapis_auth.http_client_base_test;

import 'dart:async';

import 'package:googleapis_auth/src/http_client_base.dart';
import 'package:unittest/unittest.dart';
import 'package:http/http.dart';

import 'test_utils.dart';

class DelegatingClientImpl extends DelegatingClient {
  DelegatingClientImpl(Client base, {bool closeUnderlyingClient})
      : super(base, closeUnderlyingClient: closeUnderlyingClient);

  Future send(request) => throw 'unsupported';
}


main() {
  group('http-utils', () {
    group('delegating-client', () {
      test('not-close-underlying-client', () {
        var mock = mockClient((_) {}, expectClose: false);
        new DelegatingClientImpl(mock, closeUnderlyingClient: false).close();
      });

      test('close-underlying-client', () {
        var mock = mockClient((_) {}, expectClose: true);
        new DelegatingClientImpl(mock, closeUnderlyingClient: true).close();
      });

      test('close-several-times', () {
        var mock = mockClient((_) {}, expectClose: true);
        var delegate =
            new DelegatingClientImpl(mock, closeUnderlyingClient: true);
        delegate.close();
        expect(() => delegate.close(), throwsA(isStateError));
      });
    });

    group('refcounted-client', () {
      test('not-close-underlying-client', () {
        var mock = mockClient((_) {}, expectClose: false);
        var client = new RefCountedClient(mock, initialRefCount: 3);
        client.close();
        client.close();
      });

      test('close-underlying-client', () {
        var mock = mockClient((_) {}, expectClose: true);
        var client = new RefCountedClient(mock, initialRefCount: 3);
        client.close();
        client.close();
        client.close();
      });

      test('acquire-release', () {
        var mock = mockClient((_) {}, expectClose: true);
        var client = new RefCountedClient(mock, initialRefCount: 1);
        client.acquire();
        client.release();
        client.acquire();
        client.release();
        client.release();
      });

      test('close-several-times', () {
        var mock = mockClient((_) {}, expectClose: true);
        var client = new RefCountedClient(mock, initialRefCount: 1);
        client.close();
        expect(() => client.close(), throwsA(isStateError));
      });
    });
    test('non-closing-client', () {
      var mock = mockClient((_) {}, expectClose: false);
      nonClosingClient(mock).close();
    });
  });
}
