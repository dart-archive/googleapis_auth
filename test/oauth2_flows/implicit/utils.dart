// Copyright (c) 2014, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:html';

// NOTE: This relies on the packages bots to checkout the package to
// third_party/pkg/googleapis_auth.
var DART_TESTING_URL_PREFIX =
    '/root_dart/third_party/pkg/googleapis_auth/test/oauth2_flows/implicit';

// NOTE for local testing:
//
// In order to run these tests without the browser controller, you can make a
// simple *html file with a <script> tag for the test and modify the following
// function to:
//    String resource(String name) => name;
String resource(String name) {
  return Uri.parse(document.baseUri)
      .resolve('$DART_TESTING_URL_PREFIX/$name')
      .toString();
}