## Googleapis Auth

This package provides support for obtaining OAuth2 credentials to access
Google APIs. It supports various OAuth2 flows.

Using this package requires creating a Google Cloud Project and obtaining
authentication credentials from there (ClientId, ServiceAccountCredentials, ...)

This package provides also two convenience features for:
 - auto refreshing OAuth2 credentials
 - obtaining authenticated HTTP clients
