// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @brief Keyvault operations definition.
 *
 */

#include "azure/keyvault/secrets/keyvault_operations.hpp"

#include "azure/keyvault/secrets/secret_client.hpp"
#include "private/secret_serializers.hpp"

Azure::Response<SecretProperties> RecoverDeletedSecretOperation::PollUntilDoneInternal(
    std::chrono::milliseconds period,
    Azure::Core::Context& context)
{
  while (true)
  {
    // Poll will update the raw response.
    Poll(context);
    if (IsDone())
    {
      break;
    }
    std::this_thread::sleep_for(period);
  }

  return Azure::Response<SecretProperties>(
      m_value, std::make_unique<Azure::Core::Http::RawResponse>(*m_rawResponse));
}

std::unique_ptr<Azure::Core::Http::RawResponse> RecoverDeletedSecretOperation::PollInternal(
    Azure::Core::Context const& context)
{
  std::unique_ptr<Azure::Core::Http::RawResponse> rawResponse;
  KeyVaultSecret secretResult;
  try
  {
    auto response = m_secretClient->GetSecret(m_continuationToken, GetSecretOptions(), context);
    secretResult = response.Value;
    rawResponse = std::move(response.RawResponse);
  }
  catch (Azure::Core::RequestFailedException& error)
  {
    rawResponse = std::move(error.RawResponse);
  }

  switch (rawResponse->GetStatusCode())
  {
    case Azure::Core::Http::HttpStatusCode::Ok:
    case Azure::Core::Http::HttpStatusCode::Forbidden: {
      m_status = Azure::Core::OperationStatus::Succeeded;
      break;
    }
    case Azure::Core::Http::HttpStatusCode::NotFound: {
      m_status = Azure::Core::OperationStatus::Running;
      break;
    }
    default:
      throw Azure::Core::RequestFailedException(rawResponse);
  }

  if (m_status == Azure::Core::OperationStatus::Succeeded)
  {
    m_value = secretResult.Properties;
  }

  return rawResponse;
}

RecoverDeletedSecretOperation::RecoverDeletedSecretOperation(
    std::shared_ptr<SecretClient> secretClient,
    Azure::Response<SecretProperties> response)
    : m_secretClient(std::move(secretClient))
{
  m_value = response.Value;

  m_rawResponse = std::move(response.RawResponse);

  m_continuationToken = m_value.Name;

  if (m_value.Name.empty() == false)
  {
    m_status = Azure::Core::OperationStatus::Succeeded;
  }
}

RecoverDeletedSecretOperation::RecoverDeletedSecretOperation(
    std::string resumeToken,
    std::shared_ptr<SecretClient> secretClient)
    : m_secretClient(std::move(secretClient)), m_continuationToken(std::move(resumeToken))
{
  m_value.Name = m_continuationToken;
}

RecoverDeletedSecretOperation RecoverDeletedSecretOperation::CreateFromResumeToken(
    std::string const& resumeToken,
    SecretClient const& client,
    Azure::Core::Context const& context)
{
  RecoverDeletedSecretOperation operation(resumeToken, std::make_shared<SecretClient>(client));
  operation.Poll(context);
  return operation;
}

Azure::Response<DeletedSecret> DeleteSecretOperation::PollUntilDoneInternal(
    std::chrono::milliseconds period,
    Azure::Core::Context& context)
{
  while (true)
  {
    Poll(context);
    if (IsDone())
    {
      break;
    }
    std::this_thread::sleep_for(period);
  }

  return Azure::Response<DeletedSecret>(
      m_value, std::make_unique<Azure::Core::Http::RawResponse>(*m_rawResponse));
}

std::unique_ptr<Azure::Core::Http::RawResponse> DeleteSecretOperation::PollInternal(
    Azure::Core::Context const& context)
{
  std::unique_ptr<Azure::Core::Http::RawResponse> rawResponse;
  Azure::Security::KeyVault::Secrets::DeletedSecret secretResult;
  try
  {
    auto response = m_secretClient->GetDeletedSecret(m_continuationToken, context);
    secretResult = response.Value;
    rawResponse = std::move(response.RawResponse);
  }
  catch (Azure::Core::RequestFailedException& error)
  {
    rawResponse = std::move(error.RawResponse);
  }

  switch (rawResponse->GetStatusCode())
  {
    case Azure::Core::Http::HttpStatusCode::Ok:
    case Azure::Core::Http::HttpStatusCode::Forbidden: {
      m_status = Azure::Core::OperationStatus::Succeeded;
      break;
    }
    case Azure::Core::Http::HttpStatusCode::NotFound: {
      m_status = Azure::Core::OperationStatus::Running;
      break;
    }
    default:
      throw Azure::Core::RequestFailedException(rawResponse);
  }

  if (m_status == Azure::Core::OperationStatus::Succeeded)
  {
    m_value = secretResult;
  }
  return rawResponse;
}

DeleteSecretOperation::DeleteSecretOperation(
    std::shared_ptr<SecretClient> secretClient,
    Azure::Response<DeletedSecret> response)
    : m_secretClient(std::move(secretClient))
{
  m_value = response.Value;
  m_rawResponse = std::move(response.RawResponse);
  m_continuationToken = m_value.Name;

  if (m_value.Name.empty() == false)
  {
    m_status = Azure::Core::OperationStatus::Succeeded;
  }
}

DeleteSecretOperation::DeleteSecretOperation(
    std::string resumeToken,
    std::shared_ptr<SecretClient> secretClient)
    : m_secretClient(std::move(secretClient)), m_continuationToken(std::move(resumeToken))
{
  m_value.Name = m_continuationToken;
}

DeleteSecretOperation DeleteSecretOperation::CreateFromResumeToken(
    std::string const& resumeToken,
    SecretClient const& client,
    Azure::Core::Context const& context)
{
  DeleteSecretOperation operation(resumeToken, std::make_shared<SecretClient>(client));
  operation.Poll(context);
  return operation;
}
