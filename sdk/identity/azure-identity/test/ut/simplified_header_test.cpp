// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @brief makes sure azure/identity.hpp can be included.
 *
 * @remark This file will catch any issue while trying to use/include the identity.hpp header
 *
 */

#include <azure/identity.hpp>

#include <gtest/gtest.h>

#if !defined(AZURE_IDENTITY_DLLEXPORT)
#error "azure/identity.hpp does not include dll_import_export.hpp"
#endif

TEST(SimplifiedHeader, identity)
{
  using namespace Azure::Identity;

  static_cast<void>(sizeof(AzureCliCredential));
  static_cast<void>(sizeof(ChainedTokenCredential));
  static_cast<void>(sizeof(ClientCertificateCredential));
  static_cast<void>(sizeof(ClientSecretCredential));
  static_cast<void>(sizeof(DefaultAzureCredential));
  static_cast<void>(sizeof(EnvironmentCredential));
  static_cast<void>(sizeof(ManagedIdentityCredential));
}
