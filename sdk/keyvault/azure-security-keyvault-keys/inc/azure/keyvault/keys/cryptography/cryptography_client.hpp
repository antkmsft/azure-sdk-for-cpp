// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file
 * @brief A client used to perform cryptographic operations with Azure Key Vault keys.
 *
 */

#pragma once

#include "azure/keyvault/keys/cryptography/cryptography_client_models.hpp"
#include "azure/keyvault/keys/cryptography/cryptography_client_options.hpp"

#include <azure/core/context.hpp>
#include <azure/core/credentials/credentials.hpp>
#include <azure/core/http/http.hpp>
#include <azure/core/internal/http/pipeline.hpp>
#include <azure/core/io/body_stream.hpp>
#include <azure/core/response.hpp>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Azure {
  namespace Security {
    namespace KeyVault {

      namespace Keys {
        namespace Cryptography {
  namespace _detail {
    /**
     * @brief The internal access to the cryptography client.
     *
     */
    class CryptoClientInternalAccess;
  } // namespace _detail

  /**
   * @brief A client used to perform cryptographic operations with Azure Key Vault keys.
   *
   */
  class CryptographyClient final {
    Azure::Core::Url m_keyId;
    std::string m_apiVersion;
    std::shared_ptr<Azure::Core::Http::_internal::HttpPipeline> m_pipeline;

  private:
    // Provide private-access to the internal layer
    friend class Azure::Security::KeyVault::Keys::Cryptography::_detail::CryptoClientInternalAccess;

    Azure::Core::Http::Request CreateRequest(
        Azure::Core::Http::HttpMethod method,
        std::vector<std::string> const& path = {},
        Azure::Core::IO::BodyStream* content = nullptr) const;

    std::unique_ptr<Azure::Core::Http::RawResponse> SendCryptoRequest(
        std::vector<std::string> const& path,
        std::string const& payload,
        Azure::Core::Context const& context) const;

    /**
     * @brief Construct a new Cryptography client that re-uses a pre-existing pipeline.
     *
     * @details This constructor is internal and accessed by a key client to create a cryptography
     * client from it.
     *
     * @remark This is an internal only API.
     *
     * @param keyId The url for the key.
     * @param apiVersion The service version to send requests to.
     * @param pipeline The already created pipeline to be use for requests.
     */
    explicit CryptographyClient(
        Azure::Core::Url keyId,
        std::string const& apiVersion,
        std::shared_ptr<Azure::Core::Http::_internal::HttpPipeline> pipeline)
        : m_keyId(std::move(keyId)), m_apiVersion(apiVersion), m_pipeline(std::move(pipeline))
    {
    }

  public:
    /**
     * @brief Initializes a new instance of the #CryptographyClient class.
     *
     * @param keyId The key identifier of the #Azure::Security::KeyVault::Keys::KeyVaultKey which
     * will be used for cryptographic operations.
     * @param credential An Azure::Core::Credentials::TokenCredential used to authenticate requests
     * to the vault, like DefaultAzureCredential.
     * @param options #Azure::Security::KeyVault::Keys::Cryptography::CryptographyClientOptions for
     * the #CryptographyClient for local or remote operations on Key Vault.
     */
    explicit CryptographyClient(
        std::string const& keyId,
        std::shared_ptr<const Core::Credentials::TokenCredential> credential,
        CryptographyClientOptions const& options = CryptographyClientOptions());

    /**
     * @brief Destructs `%CryptographyClient`.
     *
     */
    ~CryptographyClient();

    /**
     * @brief Encrypts plaintext.
     *
     * @param parameters An #Azure::Security::KeyVault::Keys::Cryptography::EncryptParameters
     * containing the data to encrypt and other parameters for algorithm-dependent encryption.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return An #Azure::Security::KeyVault::Keys::Cryptography::EncryptResult containing the
     * encrypted data along with all other information needed to decrypt it. This information should
     * be stored with the encrypted data.
     */
    Azure::Response<EncryptResult> Encrypt(
        EncryptParameters const& parameters,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Decrypts ciphertext.
     *
     * @param parameters A #Azure::Security::KeyVault::Keys::Cryptography::DecryptResult containing
     * the data to decrypt and other parameters for algorithm-dependent Decryption.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return An #Azure::Security::KeyVault::Keys::Cryptography::DecryptResult containing the
     * decrypted data along with all other information needed to decrypt it. This information should
     * be stored with the Decrypted data.
     */
    Azure::Response<DecryptResult> Decrypt(
        DecryptParameters const& parameters,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Encrypts the specified key.
     *
     * @param algorithm The #Azure::Security::KeyVault::Keys::Cryptography::KeyWrapAlgorithm to use.
     * @param key The key to encrypt.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return The result of the wrap operation. The returned
     * #Azure::Security::KeyVault::Keys::Cryptography::WrapResult contains the wrapped key along
     * with all other information needed to unwrap it. This information should be stored with the
     * wrapped key.
     */
    Azure::Response<WrapResult> WrapKey(
        KeyWrapAlgorithm const& algorithm,
        std::vector<uint8_t> const& key,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Decrypts the specified encrypted key.
     *
     * @param algorithm The #Azure::Security::KeyVault::Keys::Cryptography::KeyWrapAlgorithm to use.
     * @param encryptedKey The encrypted key.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return The result of the unwrap operation. The returned
     * #Azure::Security::KeyVault::Keys::Cryptography::UnwrapResult contains the key along with
     * information regarding the algorithm and key used to unwrap it.
     */
    Azure::Response<UnwrapResult> UnwrapKey(
        KeyWrapAlgorithm const& algorithm,
        std::vector<uint8_t> const& encryptedKey,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Signs the specified digest.
     *
     * @param algorithm The #Azure::Security::KeyVault::Keys::Cryptography::SignatureAlgorithm to
     * use.
     * @param digest The pre-hashed digest to sign. The hash algorithm used to compute the digest
     * must be compatable with the specified algorithm.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return The result of the sign operation. The returned
     * #Azure::Security::KeyVault::Keys::Cryptography::SignResult contains the signature along with
     * all other information needed to verify it. This information should be stored with the
     * signature.
     */
    Azure::Response<SignResult> Sign(
        SignatureAlgorithm const& algorithm,
        std::vector<uint8_t> const& digest,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Signs the specified data.
     *
     * @param algorithm The #Azure::Security::KeyVault::Keys::Cryptography::SignatureAlgorithm to
     * use.
     * @param data The data to sign.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return The result of the sign operation. The returned
     * #Azure::Security::KeyVault::Keys::Cryptography::SignResult contains the signature along with
     * all other information needed to verify it. This information should be stored with the
     * signature.
     */
    Azure::Response<SignResult> SignData(
        SignatureAlgorithm const& algorithm,
        Azure::Core::IO::BodyStream& data,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Signs the specified data.
     *
     * @param algorithm The #Azure::Security::KeyVault::Keys::Cryptography::SignatureAlgorithm to
     * use.
     * @param data The data to sign.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return The result of the sign operation. The returned
     * #Azure::Security::KeyVault::Keys::Cryptography::SignResult contains the signature along with
     * all other information needed to verify it. This information should be stored with the
     * signature.
     */
    Azure::Response<SignResult> SignData(
        SignatureAlgorithm const& algorithm,
        std::vector<uint8_t> const& data,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Verifies the specified signature.
     *
     * @param algorithm The #Azure::Security::KeyVault::Keys::Cryptography::SignatureAlgorithm to
     * use. This must be the same algorithm used to sign the digest.
     * @param digest The pre-hashed digest corresponding to the signature. The hash algorithm used
     * to compute the digest must be compatable with the specified algorithm.
     * @param signature The signature to verify.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return The result of the verify operation. If the signature is valid the
     * #VerifyResult.IsValid property of the returned
     * #Azure::Security::KeyVault::Keys::Cryptography::VerifyResult will be set to true.
     */
    Azure::Response<VerifyResult> Verify(
        SignatureAlgorithm const& algorithm,
        std::vector<uint8_t> const& digest,
        std::vector<uint8_t> const& signature,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Verifies the specified signature.
     *
     * @param algorithm The #Azure::Security::KeyVault::Keys::Cryptography::SignatureAlgorithm to
     * use. This must be the same algorithm used to sign the data.
     * @param data The data corresponding to the signature.
     * @param signature The signature to verify.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return The result of the verify operation. If the signature is valid the
     * #VerifyResult.IsValid property of the returned
     * #Azure::Security::KeyVault::Keys::Cryptography::VerifyResult will be set to true.
     */
    Azure::Response<VerifyResult> VerifyData(
        SignatureAlgorithm const& algorithm,
        Azure::Core::IO::BodyStream& data,
        std::vector<uint8_t> const& signature,
        Azure::Core::Context const& context = Azure::Core::Context());

    /**
     * @brief Verifies the specified signature.
     *
     * @param algorithm The #Azure::Security::KeyVault::Keys::Cryptography::SignatureAlgorithm to
     * use. This must be the same algorithm used to sign the data.
     * @param data The data corresponding to the signature.
     * @param signature The signature to verify.
     * @param context A Azure::Core::Context to cancel the operation.
     * @return The result of the verify operation. If the signature is valid the
     * #VerifyResult.IsValid property of the returned
     * #Azure::Security::KeyVault::Keys::Cryptography::VerifyResult will be set to true.
     */
    Azure::Response<VerifyResult> VerifyData(
        SignatureAlgorithm const& algorithm,
        std::vector<uint8_t> const& data,
        std::vector<uint8_t> const& signature,
        Azure::Core::Context const& context = Azure::Core::Context());
  };

}}}}} // namespace Azure::Security::KeyVault::Keys::Cryptography
