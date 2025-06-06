// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) TypeSpec Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

#pragma once

#include "configuration_client_models.hpp"
#include "configuration_client_options.hpp"
#include "configuration_client_paged_responses.hpp"

#include <azure/core/context.hpp>
#include <azure/core/credentials/credentials.hpp>
#include <azure/core/internal/extendable_enumeration.hpp>
#include <azure/core/internal/http/pipeline.hpp>
#include <azure/core/nullable.hpp>
#include <azure/core/paged_response.hpp>
#include <azure/core/response.hpp>
#include <azure/core/url.hpp>
#include <azure/core/uuid.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Azure { namespace Data { namespace AppConfiguration {
  class ConfigurationClient final {
  public:
    explicit ConfigurationClient(
        std::string const& url,
        const std::shared_ptr<const Core::Credentials::TokenCredential>& credential,
        ConfigurationClientOptions options = {});

    std::string GetUrl() const;

    GetKeysPagedResponse GetKeys(
        std::string const& accept,
        GetKeysOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<CheckKeysResult> CheckKeys(
        CheckKeysOptions const& options = {},
        Core::Context const& context = {}) const;

    GetKeyValuesPagedResponse GetKeyValues(
        std::string const& accept,
        GetKeyValuesOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<CheckKeyValuesResult> CheckKeyValues(
        CheckKeyValuesOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<GetKeyValueResult> GetKeyValue(
        std::string const& key,
        std::string const& accept,
        GetKeyValueOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<PutKeyValueResult> PutKeyValue(
        PutKeyValueRequestContentType const& contentType,
        std::string const& key,
        std::string const& accept,
        PutKeyValueOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<DeleteKeyValueResult> DeleteKeyValue(
        std::string const& key,
        std::string const& accept,
        DeleteKeyValueOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<CheckKeyValueResult> CheckKeyValue(
        std::string const& key,
        CheckKeyValueOptions const& options = {},
        Core::Context const& context = {}) const;

    GetSnapshotsPagedResponse GetSnapshots(
        std::string const& accept,
        GetSnapshotsOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<CheckSnapshotsResult> CheckSnapshots(
        CheckSnapshotsOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<GetSnapshotResult> GetSnapshot(
        std::string const& name,
        std::string const& accept,
        GetSnapshotOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<OperationDetails> GetOperationDetails(
        std::string const& snapshot,
        GetOperationDetailsOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<CreateSnapshotResult> CreateSnapshot(
        CreateSnapshotRequestContentType const& contentType,
        std::string const& name,
        std::string const& accept,
        Snapshot const& entity,
        CreateSnapshotOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<UpdateSnapshotResult> UpdateSnapshot(
        UpdateSnapshotRequestContentType const& contentType,
        std::string const& name,
        std::string const& accept,
        SnapshotUpdateParameters const& entity,
        UpdateSnapshotOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<CheckSnapshotResult> CheckSnapshot(
        std::string const& name,
        CheckSnapshotOptions const& options = {},
        Core::Context const& context = {}) const;

    GetLabelsPagedResponse GetLabels(
        std::string const& accept,
        GetLabelsOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<CheckLabelsResult> CheckLabels(
        CheckLabelsOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<PutLockResult> PutLock(
        std::string const& key,
        std::string const& accept,
        PutLockOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<DeleteLockResult> DeleteLock(
        std::string const& key,
        std::string const& accept,
        DeleteLockOptions const& options = {},
        Core::Context const& context = {}) const;

    GetRevisionsPagedResponse GetRevisions(
        std::string const& accept,
        GetRevisionsOptions const& options = {},
        Core::Context const& context = {}) const;

    Response<CheckRevisionsResult> CheckRevisions(
        CheckRevisionsOptions const& options = {},
        Core::Context const& context = {}) const;

  private:
    std::shared_ptr<Core::Http::_internal::HttpPipeline> m_pipeline;
    Core::Url m_url;
    std::string m_apiVersion;
  };
}}} // namespace Azure::Data::AppConfiguration
