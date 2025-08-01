# Release History

## 12.15.0-beta.2 (Unreleased)

### Features Added

### Breaking Changes

### Bugs Fixed

### Other Changes

## 12.14.0 (2025-07-21)

### Features Added

- Features in `12.14.0-beta.1` are now generally available.

## 12.15.0-beta.1 (2025-06-24)

### Features Added

- `ShareClient::DeleteIfExists()` will return `false` when error code is `ShareSnapshotNotFound`.
- Added more useful error message when the SDK encounters an x-ms-version mis-match issue.

## 12.14.0-beta.1 (2025-05-13)

### Features Added

- Added new APIs `ShareFileClient::CreateSymbolicLink()` and `ShareFileClient::GetSymbolicLink()`.

## 12.13.0 (2025-03-11)

### Features Added

- Features in `12.13.0-beta.1` are now generally available.

## 12.13.0-beta.1 (2025-02-11)

### Features Added

- Bumped up API version to `2025-05-05`.
- Added support for NFS over REST.

### Breaking Changes

- The following APIs no longer send the `x-ms-file-permission-key`, `x-ms-file-attributes`, `x-ms-file-creation-time`, and `x-ms-file-last-write-time` request headers by default. These headers have been optional in the REST API since x-ms-version `2021-06-08`:
    - `ShareFileClient::Create()`
    - `ShareFileClient::SetProperties()`
    - `ShareDirectoryClient::Create()`
    - `ShareDirectoryClient::SetProperties()`

## 12.12.0 (2024-11-12)

### Features Added

- Features in `12.12.0-beta.1` are now generally available.

## 12.12.0-beta.1 (2024-10-15)

### Features Added

- Bumped up API version to `2025-01-05`.
- Added support for the provisioned V2 billing model.
- Added support for specifying the binary file permission format for `ShareFileClient::StartCopy()`.

## 12.11.0 (2024-09-17)

### Features Added

- Features in `12.11.0-beta.1` are now generally available.

## 12.11.0-beta.1 (2024-08-07)

### Features Added

- Bumped up API version to `2024-11-04`.
- Added support for token-based authentication for all APIs.
- Added support for paid bursting on premium file share accounts.
- Added support for binary format for file permissions.
- Added ability to retrieve SAS string to sign for debugging purposes.

## 12.10.0 (2024-07-16)

### Features Added

- Features in `12.10.0-beta.1` are now generally available.

## 12.10.0-beta.1 (2024-06-11)

### Features Added

- Bumped up API version to `2024-08-04`.
- Added more detailed messaging for authorization failure cases.
- Added support for snapshot management on NFS shares.

## 12.9.0 (2024-05-07)

### Features Added

- Features in `12.9.0-beta.1` are now generally available.

## 12.9.0-beta.1 (2024-04-17)

### Features Added

- Added new field `ClientName` in `HandleItem`.
- Added new field `IncludeRenames` in `GetFileRangeListOptions`.

## 12.8.0 (2023-11-07)

### Features Added

- Features in `12.8.0-beta.1` are now generally available.
- Fixed a bug where the x-ms-file-request-intent request header was not being sent for `ShareFileClient::UploadRangeFromUri`.

## 12.8.0-beta.1 (2023-10-17)

### Features Added

- Added new extendable enum `ShareAudience`
- Added new field `Audience` in `ShareClientOptions`

## 12.7.0 (2023-09-12)

### Features Added

- Features in `12.7.0-beta.1` and `12.7.0-beta.2` are now generally available.

### Bugs Fixed

- Fixed a bug where `ShareServiceClient::SetProperties` and `ShareServiceClient::GetProperties` threw exception if property `Protocol` is not null.

## 12.7.0-beta.1 (2023-08-12)

### Features Added

- TenantId can now be discovered through the service challenge response, when using a TokenCredential for authorization.
    - A new property is now available on `ShareClientOptions` called `EnableTenantDiscovery`. If set to `true`, the client will attempt an initial unauthorized request to the service to prompt a challenge containing the tenantId hint.
- Added a new field `SourceAuthorization` in options for copy operations, which can be used to specify authorization for copy source.
- Added a new field `ContentType` in `RenameFileOptions`.

## 12.6.1 (2023-08-08)

### Bugs Fixed

- Fixed a bug where `ShareDirectoryClient::ListFilesAndDirectories` only returns the first page without ContinuationToken, even if there are more pages.

## 12.6.0 (2023-07-11)

### Features Added

- New features in `12.6.0-beta.1` are now generally available.

## 12.6.0-beta.1 (2023-05-31)

### Features Added
- Bumped up API version to `2023-01-03`.
- Added new field `AccessRights` in `HandleItem`.

## 12.5.0 (2023-05-09)

### Features Added

- New features in `12.5.0-beta.1` are now generally available.

### Bugs Fixed

- Fixed a bug where `ShareFileClient::ListHandles` and `ShareDirectoryClient::ListHandles` always return empty list.

## 12.5.0-beta.1 (2023-04-11)

### Features Added

- Added support for OAuth:
  - New field `ShareTokenIntent` in ShareClientOptions.
  - New constructor with `TokenCredential` in `ShareServiceClient`, `ShareClient`, `ShareDirectoryClient`, `ShareFileClient`.
- Added support for trailing dot:
  - New field `AllowTrailingDot`,  `AllowSourceTrailingDot` in `ShareClientOptions`.

## 12.4.0 (2023-03-07)

### Features Added

- New features in `12.4.0-beta.1` are now generally available.

### Bugs Fixed

- Fixed a bug where `ShareClient::GetStatistics` threw exception when storage service doesn't return `ETag` and `Last-Modified` headers.

## 12.4.0-beta.1 (2023-02-07)

### Features Added

- Bumped up API version to `2021-12-02`.
- Added support for invalid xml characters in file and directory names for `ShareDirectoryClient::ListFilesAndDirectories()`, `ShareDirectoryClient::ListHandles()` and `ShareFileClient::ListHandles()`.

### Acknowledgments

Thank you to our developer community members who helped to make Azure Storage File Shares better with their contributions to this release:

- ariellink _([GitHub](https://github.com/Ariellink))_

## 12.3.0 (2022-10-11)

### Features Added

- New features in `12.3.0-beta.1` are now generally available.

## 12.3.0-beta.1 (2022-09-06)

### Features Added

- Bumped up API version to `2021-06-08`.
- Added fields `ProvisionedBandwidthMBps`, `EnabledProtocols` and `RootSquash` in `ShareItemDetails` and `ShareProperties`.
- Added support for listing files with extended information.
- Added new APIs:
  - ShareDirectoryClient::RenameFile()
  - ShareDirectoryClient::RenameSubdirectory()
  - ShareLeaseClient::Renew()
- Added support for specifying last written time when uploading file range.
- Added support for specifying file changed time when creating/copying file or setting file properties.

### Bugs Fixed

- Empty file or existing file won't be created/overwritten if the file to be downloaded doesn't exist.

## 12.2.1 (2022-03-09)

### Other Changes

- Deprecated enum `LeaseDuration`, use `LeaseDurationType` instead.

## 12.2.0 (2021-09-08)

### Breaking Changes

- `AccessPolicy::StartsOn` and `AccessPolicy::ExpiresOn` are now nullable values.

### Bugs Fixed

- Fixed a bug where prefix cannot contain `&` when listing files.

### Other Changes

- Create less threads if there isn't too much data to transfer.

## 12.1.0 (2021-08-10)

### Bugs Fixed

- Fixed a bug where unspecified SMB properties got overwritten rather than preserved by `SetProperties()`.

## 12.0.1 (2021-07-07)

No API changes since `12.0.0`.

## 12.0.0 (2021-06-08)

### Breaking Changes

- Renamed `ContentLength` in `FileItemDetails` to `FileSize`.

### Other Changes and Improvements

- Updated some samples.
- Fixed a read consistency issue.

## 12.0.0-beta.11 (2021-05-19)

### New Features

- Added `ShareDirectoryClient::ForceCloseAllHandles()` and `ShareFileClient::ForceCloseAllHandles()`.

### Breaking Changes

- Added `final` specifier to classes and structures that are are not expected to be inheritable at the moment.
- Renamed `HasMorePages()` in paged response to `HasPage()`.
- `ShareLeaseClient::Change()` updates internal lease id.
- `ShareItem::ShareMetadata` was renamed to `ShareItem::Metadata`.

## 12.0.0-beta.10 (2021-04-16)

### Breaking Changes

- Removed `Azure::Storage::Files::Shares::PackageVersion`.
- Renamed `GetUserDelegationKeyOptions::startsOn` to `StartsOn`.
- Removed `ShareClient::ListFilesAndDirectories()`.
- Replaced all paginated collection functions that have the SinglePage suffix with pageable functions returning a `PagedResponse<T>`-derived type. The options are also renamed accordingly.
  - `ShareServiceClient::ListShares()`.
  - `ShareDirectoryClient::ListFilesAndDirectories()`.
  - `ShareDirectoryClient::ListHandles()`.
  - `ShareFileClient::ListHandles()`.
- Removed `ShareDirectoryClient::ForceCloseAllHandlesSinglePage()` and `ShareFileClient::ForceCloseAllHandlesSinglePage()`.
  
## 12.0.0-beta.9 (2021-03-23)

### New Features

- Added support for telemetry options.
- Added `Azure::Storage::Files::Shares::PackageVersion`.

### Breaking Changes

- Changed the return type of `StartCopy` API from a `Response<T>` to the particular `Operation<T>` type called `StartFileCopyOperation` directly.
- String conversion functions of extensible enums were renamed from `Get()` to `ToString()`.
- Changed the return types of the following APIs:
  - `ShareClient::GetAccessPolicy` now returns `ShareAccessPolicy`.
  - `ShareClient::GetPermission` now returns `std::string`.
  - `ShareClient::AbortCopy` now returns `AbortFileCopyResult`.
- Renamed `GetShareStatisticsResult` to `ShareStatistics`.
- Renamed `GetSharePropertiesResult` to `ShareProperties`.
- Renamed `GetShareDirectoryPropertiesResult` to `DirectoryProperties`.
- Renamed `GetShareFilePropertiesResult` to `FileProperties`
- Renamed `GetServicePropertiesResult` to `ShareServiceProperties`.
- Removed `Share` from the names of return types and option types.
- Renamed `AbortCopyFileOptions` to `AbortFileCopyOptions`.
- Removed `RequestId` from the return types.
- Changed `BodyStream` parameter of `UploadRange` function from pointer to reference.
- Removed `PreviousShareSnapshot` from `GetShareFileRangeListOptions`, use `ShareFileClient::GetRangeListDiff` instead.
- Renamed `ShareAccessTier` to `AccessTier`.
- Renamed `ShareRetentionPolicy` to `RetentionPolicy`.
- Renamed `ShareProtocolSettings` to `ProtocolSettings`.
- Renamed `CopyStatusType` to `CopyStatus`
- Removed `FileRangeWriteType`, `ShareFileRangeList`, `FileRangeWriteFromUrlType`, `FileRange`, `ClearRange`, `SharePermission`, `LeaseAction` and `ShareStats`.
- Renamed `LeaseDurationType` to `LeaseDuration`, `LeaseStateType` to `LeaseState` and `LeaseStatusType` to `LeaseStatus`.
- Renamed `ListSharesIncludeType` to `ListSharesIncludeFlags`.
- Renamed `DeleteSnapshotsOptionType` to `DeleteSnapshotsOption`.
- Renamed `PermissionCopyModeType` to `PermissionCopyMode`.

## 12.0.0-beta.8 (2021-02-12)

### New Features

- Changed type of `FileAttributes` to extensible enum.

### Breaking Changes

- `ListSharesSinglePageOptions::ListSharesInclude` was renamed to `ListSharesSinglePageOptions::ListSharesIncludeFlags`.
- `DeleteShareOptions::IncludeSnapshots` was renamed to `DeleteShareOptions::DeleteSnapshots`.
- `FileShareSmbProperties` was renamed to `FileSmbProperties`.
- `DownloadShareFileOptions::GetRangeContentMd5` was renamed to `DownloadShareFileOptions::RangeHashAlgorithm`.
- `UploadFileRangeFromUriOptions::SourceContentHash` was renamed to `UploadFileRangeFromUriOptions::TransactionalContentHash`.
- `GetShareFileRangeListOptions::PrevShareSnapshot` was renamed to `GetShareFileRangeListOptions::PreviousShareSnapshot`.
- Refined `CreateShareDirectoryResult` and `CreateShareFileResult`.
- Removed `DownloadShareFileDetails::AcceptRanges`.
- Removed `GetShareFilePropertiesResult::FileType`.
- Added `RequestId` in `ForceCloseShareDirectoryHandleResult`.
- Removed `TransactionalContentHash` from `ClearShareFileRangeResult`.
- Changed API signature of `ShareFileClient::UploadRangeFromUri`.
- Renamed `ForceCloseAllHandles` to `ForceCloseAllHandlesSinglePage` and all related structs.
- Made all `ContinuationToken` in return types nullable.
- Renamed `ShareFileHttpHeaders` to `FileHttpHeaders`.
- Renamed `ShareGetPropertiesResult::AccessTierChangeTime` to `AccessTierChangedOn`.
- Renamed `ShareGetStatisticsResult::ShareUsageBytes` to `ShareUsageInBytes`.
- Renamed `ShareGetPermissionResult::Permission` to `FilePermission`.
- Grouped all file SMB properties into a struct and refined the APIs that return these properties.
- Renamed `numberOfHandlesClosed` to `NumberOfHandlesClosed` and `numberOfHandlesFailedToClose` to `NumberOfHandlesFailedToClose`.
- Renamed `FileGetRangeListResult::FileContentLength` to `FileSize`.
- Renamed `StorageServiceProperties` to `FileServiceProperties`.
- Removed `LeaseTime` in results returned by lease operations. Also removed `LeaseId` in `ShareBreakLeaseResult`.
- Moved `Azure::Core::Context` out of options bag of each API, and make it the last optional parameter.

## 12.0.0-beta.7 (2021-02-04)

### New Features

- Added support for `UploadRangeFromUri` in file client.
- Added support for `SetProperties` in share client. This API supports update share tier and adjusting share's quota.
- Added support to get share's tier status in `ListSharesSinglePage` and `GetProperties`.
- Added `ChangedOn`, `FileId`, `ParentId` to the `FileShareSmbProperties`.

### Breaking Changes

- Removed `GetDirectoryClient` and `GetFileClient` from `ShareClient`. `ShareDirectoryClient` and `ShareFileClient` now initializes with the name of the resource, not path, to indicate that no path parsing is done for the API
- `ContentRange` in `FileDownloadResult` is now `Azure::Core::Http::Range`.
- `ContentLength` in `FileDownloadResult` is renamed to `FileSize`.
- Renamed `GetUri` to `GetUrl`.
- Moved all protocol layer generated result types to `Details` namespace.
- Renamed `ShareItems` in `ListSharesResponse` to `Items`.
- Renamed `ShareItems` in `ServiceListSharesSinglePageResult` to `Items`.
- Added `ShareLeaseClient`, all lease related APIs are moved to `ShareLeaseClient`.
- Changed lease duration to be `std::chrono::seconds`.
- Added `RequestId` in each return types for REST API calls, except for concurrent APIs.
- Removed `PreviousContinuationToken` from `ListFilesAndDirectoriesSinglePageResult` and `ListSharesSinglePageResult`.
- Removed `c_` for constants: `c_FileDefaultTimeValue`, `c_FileCopySourceTime`, `c_FileInheritPermission`, `FilePreserveSmbProperties` and `FileAllHandles`.
- `Concurrency`, `ChunkSize` and `InitialChunkSize` were moved into `DownloadShareFileToOptions::TansferOptions`.
- `Concurrency`, `ChunkSize` and `SingleUploadThreshold` were moved into `UploadShareFileFromOptions::TransferOptions`.
- Removed `SetQuota` related API, result and options. The functionality is moved into `SetProperties`.
- Moved some less commonly used properties returned when downloading a file into a new structure called `DownloadShareFileDetails`. This will impact the return type of `ShareFileClient::Download` and `ShareFileClient::DownloadTo`.
- Renamed `FileProperty` to `FileItemDetails` to align with other SDK's naming pattern for returned items for list operation.
- Renamed `ShareProperties` to `ShareItemDetails` to align with other SDK's naming pattern for returned items for list operation.

### Other Changes and Improvements

- Removed `c_` for constants and renamed to pascal format.

## 12.0.0-beta.6 (2021-01-14)

### New Features

- Added support for `CreateIfNotExists` for Share and Directory clients, and `DeleteIfExists` for Share, Directory and File clients.
- Support setting file SAS permission with a raw string.

### Breaking Changes

- Removed constructors in clients that takes a `Azure::Identity::ClientSecretCredential`.
- Removed Share Lease related APIs such as `ShareClient::AcquireLease` and `ReleaseLease` since they are not supported in recent service versions.
- Moved File SAS into `Azure::Storage::Sas` namespace.
- Replaced all transactional content MD5/CRC64 with the `ContentHash` struct.
- `FileShareHttpHeaders` is renamed to `ShareFileHttpHeaders`, and member `std::string ContentMd5` is changed to `Storage::ContentHash ContentHash`.
- All date time related strings are now changed to `Azure::Core::DateTime` type.
- Moved version strings into `Details` namespace.
- Renamed all functions and structures that could retrieve partial query results from the server to have `SinglePage` suffix instead of `Segment` suffix.
- Removed `FileRange`, `ClearRange`, and `Offset` and `Length` pair in options. They are now represented with `Azure::Core::Http::Range`.
- Replace scoped enums that don't support bitwise operations with extensible enum.
- `IsServerEncrypted` members in `DownloadFileToResult`, `UploadFileFromResult`, `FileDownloadResult` and `FileGetPropertiesResult` are no longer nullable.
- Create APIs for Directory and File now returns `FileShareSmbProperties` that aggregates SMB related properties.
- `DirectoryClient` is renamed to `ShareDirectoryClient`, `FileClient` is renamed to `ShareFileClient`.
- Directory and File related result types and options types now have a `Share` prefix. For example, `SetDirectoryPropertiesResult` is changed to `SetShareDirectoryPropertiesResult`.
- Renamed `GetSubDirectoryClient` to `GetSubdirectoryClient`.
- Type for ETag was changed to `Azure::Core::ETag`.

## 12.0.0-beta.5 (2020-11-13)

### Breaking Changes

- `Azure::Storage::Files::Shares::Metrics::IncludeAPIs` is now renamed to `Azure::Storage::Files::Shares::Metrics::IncludeApis`, and is changed to a nullable member.
- Moved header `azure/storage/files/shares/shares.hpp` to `azure/storage/files/shares.hpp`.
- Moved returning model types and related functions in `Azure::Storage::Files::Shares` to `Azure::Storage::Files::Shares::Models`, and made other code private by moving it into `Azure::Storage::Files::Shares::Details`.
- Renamed `Azure::Storage::Files::Shares::ServiceClient` to `Azure::Storage::Files::Shares::ShareServiceClient`.

## 1.0.0-beta.4 (2020-10-16)

### New Features

- Service version is now 2020-02-10.
- Added support for leasing a share:
  - ShareClient::AcquireLease
  - ShareClient::ReleaseLease
  - ShareClient::ChangeLease
  - ShareClient::BreakLease
  - ShareClient::RenewLease

### Breaking Changes

- `CreateFromConnectionString` now accepts unencoded file and directory name.
- Added support for getting range list with previous snapshot. `GetFileRangeListResult` now returns `std::vector<FileRange> Ranges` and `std::vector<FileRange> ClearRanges` instead of `std::vector<Range> RangeList`.
- Added support for SMB Multi-Channel setting for `ServiceClient::GetProperties` and `ServiceClient::SetProperties`. This is only available for Storage account with Premium File access.
  - Standard account user has to remove the returned SMB Multi-Channel setting before set, otherwise service would return failure.
- `Marker` is renamed to `ContinuationToken` in options.
- `NextMarker` is renamed to `ContinuationToken` in returned result objects.
- `Marker` is renamed to `PreviousContinuationToken` in returned result objects.

### Bug Fixes

- Unencoded Share/File/Directory name is now encoded.

## 1.0.0-beta.2 (2020-09-09)

### New Features

- Added File SAS generation support.
- Release based on azure-core_1.0.0-beta.1.

## 1.0.0-beta.1 (2020-08-28)

### New Features

- Added support for File features:
  - ServiceClient::ListSharesSegment
  - ServiceClient::SetProperties
  - ServiceClient::GetProperties
  - ShareClient::Create
  - ShareClient::Delete
  - ShareClient::CreateSnapshot
  - ShareClient::GetProperties
  - ShareClient::SetQuota
  - ShareClient::SetMetadata
  - ShareClient::GetAccessPolicy
  - ShareClient::SetAccessPolicy
  - ShareClient::GetStatistics
  - ShareClient::CreatePermission
  - ShareClient::GetPermission
  - ShareClient::ListFilesAndDirectoriesSegment
  - DirectoryClient::Create
  - DirectoryClient::Delete
  - DirectoryClient::GetProperties
  - DirectoryClient::SetProperties
  - DirectoryClient::SetMetadata
  - DirectoryClient::ListFilesAndDirectoriesSegment
  - DirectoryClient::ListHandlesSegment
  - DirectoryClient::ForceCloseHandle
  - DirectoryClient::ForceCloseAllHandles
  - FileClient::Create
  - FileClient::Delete
  - FileClient::Download
  - FileClient::DownloadTo
  - FileClient::UploadFrom
  - FileClient::StartCopy
  - FileClient::AbortCopy
  - FileClient::GetProperties
  - FileClient::SetProperties
  - FileClient::SetMetadata
  - FileClient::UploadRange
  - FileClient::ClearRange
  - FileClient::GetRangeList
  - FileClient::ListHandlesSegment
  - FileClient::ForceCloseHandle
  - FileClient::ForceCloseAllHandles
  - FileClient::AcquireLease
  - FileClient::ReleaseLease
  - FileClient::ChangeLease
  - FileClient::BreakLease
