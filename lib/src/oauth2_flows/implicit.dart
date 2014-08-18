library googleapis_auth.implicit_gapi_flow;

import "dart:async";
import 'dart:html' as html;
import "dart:js" as js;

import '../utils.dart';
import '../../auth.dart';

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
///
class ImplicitFlow {
  final String _clientId;
  final List<String> _scopes;

  ImplicitFlow(this._clientId, this._scopes);

  Future initialize() {
    var completer = new Completer();

    js.context['dartGapiLoaded'] = () {
      var gapi = js.context['gapi']['auth'];
      gapi.callMethod('init', [() {
        completer.complete();
      }]);
    };

    var script = new html.ScriptElement();
    script.src = 'https://apis.google.com/js/client.js?onload=dartGapiLoaded';
    script.onError.first.then((errorEvent) {
      completer.completeError(new Exception('Failed to load gapi library.'));
    });
    html.document.body.append(script);

    return completer.future;
  }

  Future<AccessToken> login({bool immediate: false}) {
    var completer = new Completer();

    var gapi = js.context['gapi']['auth'];
    gapi.callMethod('authorize', [new js.JsObject.jsify({
      'client_id' : _clientId,
      'immediate' : immediate,
      'response_type' : 'token',
      'scope' : _scopes.join(' '),
    }), (jsTokenObject) {
      var tokenType = jsTokenObject['token_type'];
      var token = jsTokenObject['access_token'];
      var expiresIn = jsTokenObject['expires_in'];
      var state = jsTokenObject['state'];
      var error = jsTokenObject['error'];

      if (expiresIn is String) {
        expiresIn = int.parse(expiresIn);
      }

      if (error != null) {
        completer.completeError(new UserConsentException(
            'Failed to get user consent: $error.'));
      } else if (token == null || expiresIn is! int || tokenType != 'Bearer') {
        completer.complete(new Exception(
            'Failed to obtain user consent. Invalid server response.'));
      } else {
        completer.complete(
            new AccessToken('Bearer', token, expiryDate(expiresIn)));
      }
    }]);

    return completer.future;
  }
}
