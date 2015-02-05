## 0.2.3

- Allow `ServiceAccountCredentials` constructors to take an optional
  `user` argument to specify a user to impersonate.

## 0.2.2

- Allow `ServiceAccountCredentials.fromJson` to accept a `Map`.
- Cleaned up `README.md`

## 0.2.1
- Added optional `force` and `immediate` arguments to `runHybridFlow`.

## 0.2.0
- Renamed `forceUserConsent` parameter to `immediate`.
- Added `runHybridFlow` function to `auth_browser`, with corresponding
  `HybridFlowResult` class.

## 0.1.1
- Add `clientViaApiKey` functions to `auth_io` ad `auth_browser`.

## 0.1.0
- First release.
