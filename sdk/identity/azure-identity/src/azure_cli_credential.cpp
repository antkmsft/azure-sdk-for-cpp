// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azure/identity/azure_cli_credential.hpp"

#include "private/token_credential_impl.hpp"

#include <chrono>
#include <ctime>
#include <utility>

using Azure::Identity::AzureCliCredential;

using Azure::DateTime;
using Azure::Core::Context;
using Azure::Core::Credentials::AccessToken;
using Azure::Core::Credentials::TokenCredentialOptions;
using Azure::Core::Credentials::TokenRequestContext;
using Azure::Identity::AzureCliCredentialOptions;
using Azure::Identity::_detail::CliToolCredentialImpl;
using Azure::Identity::_detail::TokenCredentialImpl;

std::string CliToolCredentialImpl::GetAzureCliCommand(
    const std::string& scopes,
    const std::string& tenantId)
{
  std::string command = "az account get-access-token --output json --scope \"" + scopes + "\"";

  if (!tenantId.empty())
  {
    command += " --tenant \"" + tenantId + "\"";
  }

  return command;
}

AccessToken CliToolCredentialImpl::ParseAzureCliToken(
    const std::string& cliCommandOutput,
    std::function<int()> getLocalTimeToUtcDiffSeconds)
{
  // The order of elements in the vector below does matter - the code tries to find them
  // consequently, and if finding the first one succeeds, we would not attempt to parse the second
  // one. That is important, because the newer Azure CLI versions do have the new 'expires_on'
  // field, which is not affected by time zone changes. The 'expiresOn' field was the only field
  // that was present in the older versions, and it had problems, because it was a local timestamp
  // without the time zone information. So, if only the 'expires_on' is available, we try to use it,
  // and only if it is not available, we fall back to trying to get the value via 'expiresOn', which
  // we also now are able to handle correctly, except when the token expiration crosses the time
  // when the local system clock moves to and from DST.
  return TokenCredentialImpl::ParseToken(
      cliCommandOutput,
      "accessToken",
      "expiresIn",
      std::vector<std::string>{"expires_on", "expiresOn"},
      "",
      false,
      getLocalTimeToUtcDiffSeconds());
}

namespace {
int GetLocalTimeToUtcDiffSeconds()
{
#ifdef _MSC_VER
#pragma warning(push)
// warning C4996: 'localtime': This function or variable may be unsafe. Consider using localtime_s
// instead.
#pragma warning(disable : 4996)
#endif
  // LCOV_EXCL_START
  auto const timeTNow = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

  // std::difftime() returns difference in seconds.
  // We do not expect any fractional parts, but should there be any - we do not care about them.
  return static_cast<int>(
      std::difftime(std::mktime(std::localtime(&timeTNow)), std::mktime(std::gmtime(&timeTNow))));
  // LCOV_EXCL_STOP
#ifdef _MSC_VER
#pragma warning(pop)
#endif
}

AccessToken ParseAzureCliToken(const std::string& cliCommandOutput)
{
  return CliToolCredentialImpl::ParseAzureCliToken(cliCommandOutput, GetLocalTimeToUtcDiffSeconds);
}
} // namespace

AzureCliCredential::AzureCliCredential(
    Core::Credentials::TokenCredentialOptions const& options,
    std::string tenantId,
    DateTime::duration cliProcessTimeout,
    std::vector<std::string> additionallyAllowedTenants)
    : TokenCredential("AzureCliCredential"), m_cliToolCredentialImpl(
                                                 "AzureCliCredential",
                                                 std::move(tenantId),
                                                 std::move(cliProcessTimeout),
                                                 std::move(additionallyAllowedTenants),
                                                 CliToolCredentialImpl::GetAzureCliCommand,
                                                 ParseAzureCliToken)
{
}

AzureCliCredential::AzureCliCredential(AzureCliCredentialOptions const& options)
    : AzureCliCredential(
        options,
        options.TenantId,
        options.CliProcessTimeout,
        options.AdditionallyAllowedTenants)
{
}

AzureCliCredential::AzureCliCredential(const Core::Credentials::TokenCredentialOptions& options)
    : AzureCliCredential(
        options,
        AzureCliCredentialOptions{}.TenantId,
        AzureCliCredentialOptions{}.CliProcessTimeout,
        AzureCliCredentialOptions{}.AdditionallyAllowedTenants)
{
}

AccessToken AzureCliCredential::GetToken(
    TokenRequestContext const& tokenRequestContext,
    Context const& context) const
{
  return m_cliToolCredentialImpl.GetToken(tokenRequestContext, context);
}
