# Release History

## 12.11.0-beta.2 (Unreleased)

### Features Added

### Breaking Changes

### Bugs Fixed

### Other Changes

## 12.11.0-beta.1 (2025-06-24)

### Features Added

- Added more useful error message when the SDK encounters an x-ms-version mis-match issue.
- Bumped up Account SAS version to `2025-07-05`.

### Other Changes

- Added support for ICU 75.1 or later. (A community contribution, courtesy of _[kou](https://github.com/kou)_)

### Acknowledgments

Thank you to our developer community members who helped to make Azure Storage better with their contributions to this release:

- Sutou Kouhei _([GitHub](https://github.com/kou))_

## 12.10.0 (2025-03-11)

### Features Added

- Features in `12.10.0-beta.1` are now generally available.

## 12.10.0-beta.1 (2025-02-11)

### Features Added

- Bumped up Account SAS version to `2025-05-05`.

## 12.9.0 (2024-11-12)

### Features Added

- Features in `12.9.0-beta.1` are now generally available.

## 12.9.0-beta.1 (2024-10-15)

### Features Added

- Bumped up Account SAS version to `2025-01-05`.

## 12.8.0 (2024-09-17)

### Features Added

- Features in `12.8.0-beta.1` are now generally available.

## 12.8.0-beta.1 (2024-08-07)

### Features Added

- Bumped up Account SAS version to `2024-11-04`.
- Added ability to retrieve SAS string to sign for debugging purposes.

### Other Changes

- [[#5767]](https://github.com/Azure/azure-sdk-for-cpp/pull/5767) XML: Use RAII wrappers instead of manual memory management. (A community contribution, courtesy of _[rschu1ze](https://github.com/rschu1ze)_, _[alesapin](https://github.com/alesapin)_, and _[CurtizJ](https://github.com/CurtizJ)_)

### Acknowledgments

Thank you to our developer community members who helped to make Azure Storage better with their contributions to this release:

- Robert Schulze _([GitHub](https://github.com/rschu1ze))_
- alesapin _([GitHub](https://github.com/alesapin))_
- Anton Popov _([GitHub](https://github.com/CurtizJ))_

## 12.7.0 (2024-07-16)

### Features Added

- Features in `12.7.0-beta.1` are now generally available.

## 12.7.0-beta.1 (2024-06-11)

### Features Added

- Bumped up Account SAS version to `2024-08-04`.

## 12.6.0 (2024-05-07)

### Features Added

- Features in `12.6.0-beta.1` are now generally available.
- Bumped up Account SAS version to `2024-05-04`.

## 12.6.0-beta.1 (2024-04-17)

### Features Added

- Removed unnecessary dependencies on non-Windows platforms. (A community contribution, courtesy of _[teo-tsirpanis](https://github.com/teo-tsirpanis)_)

### Bugs Fixed

- Fixed a bug where exception error code was not parsed for `HEAD` requests.

### Acknowledgments

Thank you to our developer community members who helped to make Azure Storage better with their contributions to this release:

- Theodore Tsirpanis _([GitHub](https://github.com/teo-tsirpanis))_

## 12.5.0 (2023-11-07)

### Features Added

- No public changes in this release.

## 12.5.0-beta.1 (2023-10-17)

### Features Added

- No public changes in this release.

## 12.4.0 (2023-09-12)

### Features Added

- Bumped up Account SAS version to `2023-08-03`.

## 12.4.0-beta.1 (2023-08-12)

### Other Changes

- No public changes in this release.

## 12.3.3 (2023-07-11)

### Features Added

- Bumped up Account SAS version to `2023-01-03`.

## 12.3.2 (2023-05-09)

### Features Added

- Bumped up Account SAS version to `2022-11-02`.

## 12.3.1 (2023-03-07)

### Features Added

- Bumped up SAS token service version to `2021-12-02`.

## 12.3.0 (2022-09-06)

### Features Added

- Features in `12.3.0-beta.1` are now generally available.

## 12.3.0-beta.1 (2022-08-09)

### Features Added

- Added support for encryption scope SAS (`ses` query parameter in SAS token).
- Added support for permanent delete permission in SAS.

## 12.2.4 (2022-06-07)

### Bugs Fixed

- Fixed a bug where text of XML element cannot be empty.

## 12.2.3 (2022-04-06)

### Bugs Fixed

- Fixed a bug where we got error when XML request body is too big.

## 12.2.2 (2022-03-09)

### Features Added

- Added `SetImmutabilityPolicy` permission for account SAS.
- Bumped up SAS token service version to `2020-08-04`.

## 12.2.1 (2022-02-14)

### Other Changes

- No public changes in this release.

## 12.2.0 (2021-09-08)

### Features Added

- Used new xml library on Windows, dropped dependency for libxml2.

### Bugs Fixed

- Fixed a bug that may cause crash when parsing XML.

## 12.1.0 (2021-08-10)

### Bugs Fixed

- Avoid time domain casting exception during request cancellation. (A community contribution, courtesy of _[johnwheffner](https://github.com/johnwheffner)_)

### Acknowledgments

Thank you to our developer community members who helped to make Azure Storage better with their contributions to this release:

- John Heffner _([GitHub](https://github.com/johnwheffner))_

## 12.0.1 (2021-07-07)

### Bug Fixes

- Fixed a memory leak issue while parsing XML.

## 12.0.0 (2021-06-08)

### Other Changes and Improvements

- Fixed a filename encoding issue.

## 12.0.0-beta.11 (2021-05-19)

### Breaking Changes

- Added `final` specifier to classes and structures that are are not expected to be inheritable at the moment.
- Removed `Azure::PagedResponse<T>`.

### Bug Fixes

- Fixed a stream leak issue in `ReliableStream`.

## 12.0.0-beta.10 (2021-04-16)

### New Features

- Added server timeout support.
- Added `Azure::PagedResponse<T>` for returning paginated collections.

### Breaking Changes

- Removed `Azure::Storage::Common::PackageVersion`.
- Moved `ReliableStream` to internal namespace.
- Removed `HttpGetterInfo` and `HTTPGetter` from the `Azure::Storage` namespace.

## 12.0.0-beta.9 (2021-03-23)

### New Features

- Added `Azure::Storage::Common::PackageVersion`.

## 12.0.0-beta.8 (2021-02-12)

### Breaking Changes

- Removed the `Azure::Storage::Md5` class from `crypt.hpp`. Use the type from `Azure::Core::Cryptography` namespace instead, from `azure/core/cryptography/hash.hpp`.
- Renamed `Crc64` to `Crc64Hash` and change it to derive from the `Azure::Core::Cryptography::Hash` class.

## 12.0.0-beta.7 (2021-02-03)

### New Features

- Added additional information in `StorageException`.

### Breaking Changes

- `AccountSasResource::BlobContainer` was renamed to `AccountSasResource::Container`.

### Bug Fixes

- Fixed `ClientRequestId` wasn't filled in `StorageException`.

## 12.0.0-beta.6 (2021-01-14)

### New Features

- Added new type `ContentHash`.
- Added definition of `Metadata`.
- Support setting account SAS permission with a raw string.

### Breaking Changes

- Renamed `SharedKeyCredential` to `StorageSharedKeyCredential`.
- Renamed `StorageSharedKeyCredential::UpdateAccountKey` to `Update`.
- Made `StorageRetryPolicy`, `StoragePerRetryPolicy` and `SharedKeyPolicy` private by moving them to the `Details` namespace.
- Removed `StorageRetryOptions`, use `Azure::Core::Http::RetryOptions` instead.
- Moved Account SAS into `Azure::Storage::Sas` namespace.
- All date time related strings are now changed to `Azure::Core::DateTime` type.
- Made version strings private by moving them into the `Details` namespace.
- Moved `Base64Encode` and `Base64Decode` from the `Azure::Storage` namespace to `Azure::Core` and removed the string accepting overload of `Base64Encode`.
- Renamed public constants so they no longer start with the prefix `c_`. For example, `c_InfiniteLeaseDuration` became `InfiniteLeaseDuration`.

### Bug Fixes

- Fixed default EndpointSuffix when parsing a connection string. (A community contribution, courtesy of _[lordgamez](https://github.com/lordgamez)_)

### Acknowledgments

Thank you to our developer community members who helped to make Azure Storage better with their contributions to this release:

- Gabor Gyimesi _([GitHub](https://github.com/lordgamez))_

## 12.0.0-beta.5 (2020-11-13)

### Breaking Changes

- Rename `LastModifiedTimeAccessConditions` to `ModifiedTimeConditions`.
- Rename `StorageError` to `StorageException`.
- Rename header file `storage_error.hpp` to `storage_exception.hpp`.
- Rename `SharedKeyCredential::SetAccountKey` to `SharedKeyCredential::UpdateAccountKey`.
- Rename `AccountSasBuilder::ToSasQueryParameters` to `AccountSasBuilder::GenerateSasToken`.
- Remove `storage_version.hpp` and add `version.hpp`.
- Make `SharedKeyCredential` a class.

### Other Changes and Improvements

- Remove support for specifying SAS version.

## 1.0.0-beta.3 (2020-10-13)

### New Features

- Support for customizable retry policy.

## 1.0.0-beta.2 (2020-09-09)

### New Features

- Release based on azure-core_1.0.0-beta.1.

## 1.0.0-beta.1 (2020-08-28)

### New Features

- Support for Account SAS.
- Support for Base64 Encoding/Decoding.
- Support for MD5, CRC64.
- Support for Shared Key Credential.
