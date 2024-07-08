// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @brief This sample demonstrates how update a key rotation policy, and then rotate the key based
 * on the policy.
 *
 * @remark The following environment variables must be set before running the sample.
 * - AZURE_KEYVAULT_URL:  To the Key Vault account URL.
 *
 */

#include <azure/core.hpp>
#include <azure/identity.hpp>
#include <azure/keyvault/keyvault_keys.hpp>

#include <chrono>
#include <iostream>
#include <vector>

using namespace Azure::Security::KeyVault::Keys;
using namespace Azure::Security::KeyVault::Keys::Cryptography;
using namespace std::chrono_literals;

int main()
{
  auto const keyVaultUrl = std::getenv("AZURE_KEYVAULT_URL");
  auto credential = std::make_shared<Azure::Identity::ChainedTokenCredential>(
      Azure::Identity::ChainedTokenCredential::Sources{
          std ::make_shared<Azure::Identity::AzurePipelinesCredential>(
              Azure::Core::_internal::Environment::GetVariable("AZURESUBSCRIPTION_TENANT_ID"),
              Azure::Core::_internal::Environment::GetVariable("AZURESUBSCRIPTION_CLIENT_ID"),
              Azure::Core::_internal::Environment::GetVariable(
                  "AZURESUBSCRIPTION_SERVICE_CONNECTION_ID"),
              Azure::Core::_internal::Environment::GetVariable("SYSTEM_ACCESSTOKEN")),
          std::make_shared<Azure::Identity::DefaultAzureCredential>()});

  KeyClient keyClient(keyVaultUrl, credential);

  auto keyName = "RotateKey-" + Azure::Core::Uuid::CreateUuid().ToString();
  auto createKeyResponse = keyClient.CreateEcKey(CreateEcKeyOptions(keyName));

  std::cout << "Created key " << createKeyResponse.Value.Name() << "with id "
            << createKeyResponse.Value.Id() << " and version "
            << createKeyResponse.Value.Properties.Version << std::endl;

  /*  {
      "id": "https://redacted.vault.azure.net/keys/GetKeyRotationPolicy/rotationpolicy",
   "lifetimeActions": [
     {
       "trigger": {
         "timeAfterCreate": "P18M"
       },
       "action": {
         "type": "Rotate"
       }
     },
     {
       "trigger": {
         "timeBeforeExpiry": "P30D"
       },
       "action": {
         "type": "Notify"
       }
     }
   ],
   "attributes":
     {
       "expiryTime" : "P48M", "created" : 1649797765, "updated" : 1649797765
     }
   }*/

  KeyRotationPolicy policy;

  LifetimeActionsType lifetimeAction1;
  lifetimeAction1.Trigger.TimeBeforeExpiry = "P18M";
  lifetimeAction1.Action = LifetimeActionType::Notify;
  policy.LifetimeActions.emplace_back(lifetimeAction1);

  LifetimeActionsType lifetimeAction2;
  lifetimeAction2.Action = LifetimeActionType::Rotate;
  lifetimeAction2.Trigger.TimeBeforeExpiry = "P30D";
  policy.LifetimeActions.emplace_back(lifetimeAction2);

  policy.Attributes.ExpiryTime = "P48M";

  auto putPolicy = keyClient.UpdateKeyRotationPolicy(keyName, policy).Value;

  std::cout << "Updated rotation policy " << putPolicy.Id << " for key "
            << createKeyResponse.Value.Name() << std::endl;

  auto originalKey = keyClient.GetKey(keyName);
  auto rotatedKey = keyClient.RotateKey(keyName);

  std::cout << "Rotated key " << originalKey.Value.Name() << std::endl
            << "Original version " << originalKey.Value.Properties.Version << std::endl
            << "New Version " << rotatedKey.Value.Properties.Version << std::endl;

  // Delete the key
  auto deleteOperation = keyClient.StartDeleteKey(keyName);
  deleteOperation.PollUntilDone(2min);
  keyClient.PurgeDeletedKey(keyName);
}
