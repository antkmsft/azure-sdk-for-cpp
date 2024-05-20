// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file
 * @brief Common implementation for CLI tool credentials.
 */

#pragma once

#include "azure/identity/detail/token_cache.hpp"

#include <azure/core/credentials/credentials.hpp>
#include <azure/core/datetime.hpp>

#include <chrono>
#include <functional>
#include <string>
#include <vector>

namespace Azure { namespace Identity { namespace _detail {

  class CliToolCredentialImpl final {
  private:
    TokenCache m_tokenCache;

    std::function<std::string(const std::string& scopes, const std::string& tenantId)>
        m_getCliCommand;

    std::function<Core::Credentials::AccessToken(const std::string& cliCommandOutput)> m_parseToken;

    std::vector<std::string> m_additionallyAllowedTenants;

    std::string m_credentialName;
    std::string m_tenantId;

    DateTime::duration m_cliProcessTimeout;

    void ThrowIfNotSafeCmdLineInput(
        std::string const& input,
        std::string const& allowedChars,
        std::string const& description) const;

  public:
    explicit CliToolCredentialImpl(
        std::string credentialName,
        std::string tenantId,
        DateTime::duration cliProcessTimeout,
        std::vector<std::string> additionallyAllowedTenants,
        std::function<std::string(const std::string& scopes, const std::string& tenantId)>
            getCliCommand,
        std::function<Core::Credentials::AccessToken(const std::string& cliCommandOutput)>
            parseToken);

    Core::Credentials::AccessToken GetToken(
        Core::Credentials::TokenRequestContext const& tokenRequestContext,
        Core::Context const& context) const;

    static std::string GetAzureCliCommand(const std::string& scopes, const std::string& tenantId);
    static Core::Credentials::AccessToken ParseAzureCliToken(
        const std::string& cliCommandOutput,
        std::function<int()> getLocalTimeToUtcDiffSeconds);
  };

}}} // namespace Azure::Identity::_detail
