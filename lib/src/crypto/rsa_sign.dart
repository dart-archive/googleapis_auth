library googleapis_auth.rsa_sign;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' show SHA256;

import 'asn1.dart';
import 'rsa.dart';


/// Used for signing messages with a private RSA key.
///
/// The implemented algorithm can be seen in
/// RFC 3447, Section 9.2 EMSA-PKCS1-v1_5.
class RS256Signer {
  // NIST sha-256 OID (2 16 840 1 101 3 4 2 1)
  // See a reference for the encoding here:
  // http://msdn.microsoft.com/en-us/library/bb540809%28v=vs.85%29.aspx
  static const _RSA_SHA256_ALGORITHM_IDENTIFIER =
      const [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

  final RSAPrivateKey _rsaKey;

  RS256Signer(this._rsaKey);

  List<int> sign(List<int> bytes) {
    var hash = (new SHA256()..add(bytes)).close();
    var digest = _digestInfo(hash);

    var keyLen = (_rsaKey.n.bitLength + 7) ~/ 8;
    var block = new Uint8List(keyLen);
    var padLength = block.length - digest.length - 3;
    block[0] = 0x00;
    block[1] = 0x01;
    block.fillRange(2, 2 + padLength, 0xFF);
    block[2 + padLength] = 0x00;
    block.setRange(2 + padLength + 1, block.length, digest);

    return RSAAlgorithm.encrypt(_rsaKey, block);
  }

  static Uint8List _digestInfo(List<int> hash) {
    // DigestInfo :== SEQUENCE {
    //     digestAlgorithm AlgorithmIdentifier,
    //     digest OCTET STRING
    // }
    var offset = 0;
    var digestInfo = new Uint8List(
        2 + 2 + _RSA_SHA256_ALGORITHM_IDENTIFIER.length + 2 + 2 + hash.length);
    {
      // DigestInfo
      digestInfo[offset++] = ASN1Parser.SEQUENCE_TAG;
      digestInfo[offset++] = digestInfo.length - 2;
      {
        // AlgorithmIdentifier.
        digestInfo[offset++] = ASN1Parser.SEQUENCE_TAG;
        digestInfo[offset++] = _RSA_SHA256_ALGORITHM_IDENTIFIER.length + 2;
        digestInfo.setAll(offset, _RSA_SHA256_ALGORITHM_IDENTIFIER);
        offset += _RSA_SHA256_ALGORITHM_IDENTIFIER.length;
        digestInfo[offset++] = ASN1Parser.NULL_TAG;
        digestInfo[offset++] = 0;
      }
      digestInfo[offset++] = ASN1Parser.OCTET_STRING_TAG;
      digestInfo[offset++] = hash.length;
      digestInfo.setAll(offset, hash);
    }
    return digestInfo;
  }
}
