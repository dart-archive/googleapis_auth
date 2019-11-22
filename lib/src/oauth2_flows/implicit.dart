// Copyright (c) 2014, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library googleapis_auth.implicit_gapi_flow;

import "dart:async";
import 'dart:html' as html;
import "dart:js" as js;

import '../../auth.dart';
import '../utils.dart';

// This will be overridden by tests.
String gapiUrl = 'https://apis.google.com/js/client.js';

// According to the CSP3 spec a nonce must be a valid base64 string.
// https://w3c.github.io/webappsec-csp/#grammardef-base64-value
final _noncePattern = new RegExp('^[\\w+\/_-]+[=]{0,2}\$');

/// This class performs the implicit browser-based oauth2 flow.
///
/// It has to be used in two steps:
///
/// 1. First call initialize() and wait until the Future completes successfully
///    - loads the 'gapi' JavaScript library into the current document
///    - wait until the library signals it is ready
///
/// 2. Call login() as often as needed.
///    - will call the 'gapi' JavaScript lib to trigger an oauth2 browser flow
///      => This might create a popup which asks the user for consent.
///    - will wait until the flow is completed (successfully or not)
///      => Completes with AccessToken or an Exception.
/// 3. Call loginHybrid() as often as needed.
///    - will call the 'gapi' JavaScript lib to trigger an oauth2 browser flow
///      => This might create a popup which asks the user for consent.
///    - will wait until the flow is completed (successfully or not)
///      => Completes with a tuple [AccessCredentials cred, String authCode]
///         or an Exception.
class ImplicitFlow {
  static const CallbackTimeout = const Duration(seconds: 20);

  final String _clientId;
  final List<String> _scopes;

  /// The pending result of an earlier call to [initialize], if any.
  ///
  /// There can be multiple [ImplicitFlow] objects in an application,
  /// but the gapi JS library should only ever be loaded once. If
  /// it's called again while a previous initialization is still pending,
  /// this will be returned.
  static Future<void> _pendingInitialization;

  ImplicitFlow(this._clientId, this._scopes);

  /// Readies the flow for calls to [login] by loading the 'gapi'
  /// JavaScript library, or returning the [Future] of a pending
  /// initialization if any object has called this method already.
  Future<void> initialize() {
    if (_pendingInitialization != null) {
      return _pendingInitialization;
    }

    var completer = new Completer();

    var timeout = new Timer(CallbackTimeout, () {
      _pendingInitialization = null;
      completer.completeError(new Exception(
          'Timed out while waiting for the gapi.auth library to load.'));
    });

    js.context['dartGapiLoaded'] = () {
      timeout.cancel();
      try {
        var gapi = js.context['gapi']['auth'];
        try {
          gapi.callMethod('init', [
            () {
              completer.complete();
            }
          ]);
        } on NoSuchMethodError {
          throw new StateError('gapi.auth not loaded.');
        }
      } catch (error, stack) {
        _pendingInitialization = null;
        if (!completer.isCompleted) {
          completer.completeError(error, stack);
        }
      }
    };

    var script = _createScript();
    script.src = '${gapiUrl}?onload=dartGapiLoaded';
    script.onError.first.then((errorEvent) {
      timeout.cancel();
      _pendingInitialization = null;
      if (!completer.isCompleted) {
        // script loading errors can still happen after timeouts
        completer.completeError(new Exception('Failed to load gapi library.'));
      }
    });
    html.document.body.append(script);

    _pendingInitialization = completer.future;
    return completer.future;
  }

  Future<LoginResult> loginHybrid(
          {bool force: false, bool immediate: false, String loginHint}) =>
      _login(force, immediate, true, loginHint, null);

  Future<AccessCredentials> login(
      {bool force: false,
      bool immediate: false,
      String loginHint,
      List<ResponseType> responseTypes}) async {
    return (await _login(force, immediate, false, loginHint, responseTypes))
        .credential;
  }

  // Completes with either credentials or a tuple of credentials and authCode.
  //  hybrid  =>  [AccessCredentials credentials, String authCode]
  // !hybrid  =>  AccessCredentials
  //
  // Alternatively, the response types can be set directly if `hybrid` is not
  // set to `true`.
  Future<LoginResult> _login(bool force, bool immediate, bool hybrid,
      String loginHint, List<ResponseType> responseTypes) {
    assert(hybrid != true || responseTypes?.isNotEmpty != true);

    var completer = new Completer<LoginResult>();

    var gapi = js.context['gapi']['auth'];

    var json = {
      'client_id': _clientId,
      'immediate': immediate,
      'approval_prompt': force ? 'force' : 'auto',
      'response_type': responseTypes?.isNotEmpty == true
          ? responseTypes
              .map((responseType) => _responseTypeToString(responseType))
              .join(' ')
          : hybrid ? 'code token' : 'token',
      'scope': _scopes.join(' '),
      'access_type': hybrid ? 'offline' : 'online',
    };

    if (loginHint != null) {
      json['login_hint'] = loginHint;
    }

    gapi.callMethod('authorize', [
      new js.JsObject.jsify(json),
      (jsTokenObject) {
        var tokenType = jsTokenObject['token_type'];
        var token = jsTokenObject['access_token'];
        var expiresInRaw = jsTokenObject['expires_in'];
        var code = jsTokenObject['code'];
        var error = jsTokenObject['error'];
        var idToken = jsTokenObject['id_token'];

        var expiresIn;
        if (expiresInRaw is String) {
          expiresIn = int.parse(expiresInRaw);
        }
        if (error != null) {
          completer.completeError(
              new UserConsentException('Failed to get user consent: $error.'));
        } else if (token == null ||
            expiresIn is! int ||
            tokenType != 'Bearer') {
          completer.completeError(new Exception(
              'Failed to obtain user consent. Invalid server response.'));
        } else if (responseTypes?.contains(ResponseType.idToken) == true &&
            idToken?.isNotEmpty != true) {
          completer.completeError(
              new Exception('Expected to get id_token, but did not.'));
        } else {
          var accessToken =
              new AccessToken('Bearer', token, expiryDate(expiresIn));
          var credentials = new AccessCredentials(accessToken, null, _scopes,
              idToken: idToken);

          if (hybrid) {
            if (code == null) {
              completer.completeError(new Exception('Expected to get auth code '
                  'from server in hybrid flow, but did not.'));
              return;
            }
            completer.complete(new LoginResult(credentials, code: code));
          } else {
            completer.complete(new LoginResult(credentials));
          }
        }
      }
    ]);

    return completer.future;
  }
}

class LoginResult {
  final AccessCredentials credential;
  final String code;

  LoginResult(this.credential, {this.code});
}

/// Convert [responseType] to string value expected by `gapi.auth.authorize`.
String _responseTypeToString(ResponseType responseType) {
  String result;

  switch (responseType) {
    case ResponseType.code:
      result = 'code';
      break;

    case ResponseType.idToken:
      result = 'id_token';
      break;

    case ResponseType.permission:
      result = 'permission';
      break;

    case ResponseType.token:
      result = 'token';
      break;

    default:
      throw ArgumentError('Unknown response type: $responseType');
  }

  return result;
}

/// Creates a script that will run properly when strict CSP is enforced.
///
/// More specifically, the script has the correct `nonce` value set.
final _ScriptFactory _createScript = (() {
  final nonce = _getNonce();
  if (nonce == null) return () => new html.ScriptElement();

  return () => new html.ScriptElement()..nonce = nonce;
})();

typedef html.ScriptElement _ScriptFactory();

/// Returns CSP nonce, if set for any script tag.
String _getNonce({html.Window window}) {
  final currentWindow = window ?? html.window;
  final elements = currentWindow.document.querySelectorAll('script');
  for (final element in elements) {
    final nonceValue =
        (element as html.HtmlElement).nonce ?? element.attributes['nonce'];
    if (nonceValue != null && _noncePattern.hasMatch(nonceValue)) {
      return nonceValue;
    }
  }
  return null;
}
