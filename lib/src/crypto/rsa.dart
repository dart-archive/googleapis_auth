/*
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */

library googleapis_auth.rsa;

import 'dart:typed_data';

/// Represents integers obtained while creating a Public/Private key pair.
class RSAPrivateKey {
  /// First prime number.
  final int p;

  /// Second prime number.
  final int q;

  /// Modulus for public and private keys. Satisfies `n=p*q`.
  final int n;

  /// Public key exponent. Satisfies `d*e=1 mod phi(n)`.
  final int e;

  /// Private key exponent. Satisfies `d*e=1 mod phi(n)`.
  final int d;

  /// Different form of [p]. Satisfies `dmp1=d mod (p-1)`.
  final int dmp1;

  /// Different form of [p]. Satisfies `dmq1=d mod (q-1)`.
  final int dmq1;

  /// A coefificient which satisfies `coeff=q^-1 mod p`.
  final int coeff;

  RSAPrivateKey(this.n, this.e, this.d, this.p, this.q,
                this.dmp1, this.dmq1, this.coeff);
}

/// Provides a [encrypt] method for encrypting messages with a [RSAPrivateKey].
abstract class RSAAlgorithm {

  /// Performs the encryption of [bytes] with the private [key].
  /// Others who have access to the public key will be able to decrypt this
  /// the result.
  static List<int> encrypt(RSAPrivateKey key, List<int> bytes) {
    var message = bytes2Integer(bytes);
    var encryptedMessage = _encryptInteger(key, message);
    return integer2Bytes(encryptedMessage);
   }

  static int _encryptInteger(RSAPrivateKey key, int x) {
    // The following is equivalent to `_modPow(x, key.d, key.n) but is much
    // more efficient. It exploits the fact that we have dmp1/dmq1.
    var xp = _modPow(x % key.p, key.dmp1, key.p);
    var xq = _modPow(x % key.q, key.dmq1, key.q);
    while (xp < xq) {
      xp += key.p;
    }
    return ((((xp - xq) * key.coeff) % key.p) * key.q) + xq;
  }

  static int _modPow(int b, int e, int m) {
    if (e < 1) {
      return 1;
    }
    if (b < 0 || b >  m) {
      b = b % m;
    }
    int r = 1;
    while (e > 0) {
     if ((e & 1) > 0) {
       r = (r * b) % m;
     }
     e >>= 1;
     b = (b * b) % m;
    }
    return r;
  }

  static int bytes2Integer(List<int> bytes) {
    var number = 0;
    for (var i = 0; i < bytes.length; i++) {
      number = (number << 8) | bytes[i];
    }
    return number;
  }

  static List<int> integer2Bytes(int integer) {
    if (integer < 1) {
      throw new ArgumentError('Only positive integers are supported.');
    }
    var bits = integer.bitLength;
    var numBytes = (bits + 7) ~/ 8;
    var bytes = new Uint8List(numBytes);
    for (int i = bytes.length - 1; i >= 0; i--) {
      bytes[i] = integer & 0xff;
      integer >>= 8;
    }
    return bytes;
  }
}
