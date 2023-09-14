// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azure/core/internal/environment.hpp>
#include <azure/identity/default_azure_credential.hpp>

#include <chrono>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <string>

using Azure::Core::_internal::Environment;

int main(int, char**)
{
  try
  {
    auto cred = std::make_shared<Azure::Identity::DefaultAzureCredential>();

    Azure::Core::Credentials::TokenRequestContext trc;
    trc.Scopes = {"https://vault.azure.net/.default"};
    cred->GetToken(trc, {});
  }
  catch (std::exception const& e)
  {
    std::cout << std::endl
              << std::endl
              << "----------" << std::endl
              << std::endl
              << "ERROR: Exception thrown: " << e.what() << std::endl;
  }
  catch (...)
  {
    std::cout << std::endl
              << std::endl
              << "----------" << std::endl
              << std::endl
              << "ERROR: Unknown exception" << std::endl;
  }

  return 1;
}
