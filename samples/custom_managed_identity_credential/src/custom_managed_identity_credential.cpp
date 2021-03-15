#include <azure/core/credentials/credentials.hpp>
#include <azure/core/http/curl_transport.hpp>

// This is a sample code. It provides minimum workable version of Managed Identity Credential.
// It lacks proper error handling, at least, and is not as thoroughly checked.
// But the happy path scenario does work.

// This credential must implement TokenCredential
class CustomManagedIdentityCredential : public Azure::Core::Credentials::TokenCredential {
private:
  Azure::Core::Url m_url;

  // Helper functions
  static std::string ScopesToResource(std::vector<std::string> const& scopes);
  static std::chrono::seconds ParseTokenExpiration(std::string const& responseBody);
  static std::string ParseAccessToken(std::string const& responseBody);

public:
  explicit CustomManagedIdentityCredential(
      std::string const& clientId = "" // Custom values here were not tested, but should work
      )
      : m_url("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01")
  {
    if (!clientId.empty())
    {
      m_url.AppendQueryParameter("client_id", clientId);
    }
  }

  // This TokenCredential's abstract method should be implemented
  Azure::Core::Credentials::AccessToken GetToken(
      Azure::Core::Credentials::TokenRequestContext const& tokenRequestContext,
      Azure::Core::Context const& context) const override
  {
    // Each request coming here could be for a different resource.
    // So, we copy the URL member into a local variable, to add resource query parameter for this
    // specific request.
    auto url = m_url;
    url.AppendQueryParameter("resource", ScopesToResource(tokenRequestContext.Scopes));

    // See
    // https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token#get-a-token-using-http
    // For more details.
    auto request = Azure::Core::Http::Request(Azure::Core::Http::HttpMethod::Get, url);
    request.SetHeader("Metadata", "true");

    // Here, we only work with the Curl http client implementation.
    // Production-quality implementation would need to handle any transport implementation.
    auto const response = Azure::Core::Http::CurlTransport().Send(request, context);

    // Get the clock of when the response was received, to add 'expires_in' to it.
    auto const responseReceived = std::chrono::system_clock::now();

    // Check if the response looks ok.
    if (!response || response->GetStatusCode() != Azure::Core::Http::HttpStatusCode::Ok)
    {
      throw std::exception("null response || statusCode != OK");
    }

    // Read the response body into a string.
    auto const bodyStream = response->GetBodyStream();
    auto const bodyVec = bodyStream->ReadToEnd(Azure::Core::Context());
    auto const responseBody = std::string(bodyVec.begin(), bodyVec.end());

    return {
        // Create a result of type Azure::Core::Credentials::AccessToken
        ParseAccessToken(responseBody), // First field is the token string.
        responseReceived
            + std::chrono::seconds(
                ParseTokenExpiration(responseBody)), // Second is expiration time.
    };

    // Note that we don't have to subtract a time period from expiration, on order for refresh to be
    // in time. Azure SDK's code will take care of it, and will refresh some time ahead of the
    // expiration.
  }
};

// These are helper functions.
// They parse http response body string.
// They parse JSON, but do so using primitive measures of finding characters in the string.
// That is done to avoid taking a dependency on JSON parsing, which is not a public part of Azure
// SDK.

std::string CustomManagedIdentityCredential::ScopesToResource(
    std::vector<std::string> const& scopes)
{
  // Any client SDK libraries would put scope(s) as 'https://resource.com/.default'.
  // For managed credential, we need to pass a resource ID without the '/.default'.
  // (see the link above; also other language SDKs do this).
  if (scopes.size() != 1)
  {
    // Only a single resource is supported.
    throw std::exception("scopes");
  }

  auto resource = scopes[0];
  constexpr char suffix[] = "/.default";
  constexpr int suffixLen = sizeof(suffix) - 1;
  auto const resourceLen = resource.length();

  // If scopes[0] ends with '/.default', remove it.
  if (resourceLen >= suffixLen
      && resource.find(suffix, resourceLen - suffixLen) != std::string::npos)
  {
    resource = resource.substr(0, resourceLen - suffixLen);
  }

  return resource;
}

std::chrono::seconds CustomManagedIdentityCredential::ParseTokenExpiration(
    std::string const& responseBody)
{
  auto expiresInSeconds = 0LL;

  // Find 'expires_in', and then the subsequent ':' in the HTTP response body JSON.
  constexpr auto jsonExpiresIn = "expires_in";
  auto responseBodyPos = responseBody.find(':', responseBody.find(jsonExpiresIn));
  if (responseBodyPos == std::string::npos)
  {
    // Was not found, unexpected response - throw.
    throw std::exception(jsonExpiresIn);
  }

  // Locate the integer after the 'expires_in :'
  auto const responseBodySize = responseBody.size();
  for (; responseBodyPos < responseBodySize; ++responseBodyPos)
  {
    auto c = responseBody[responseBodyPos];
    if (c != ':' && c != ' ' && c != '\"' && c != '\'')
    {
      break;
    }
  }

  // String to int (or, to be precise, to long)
  for (; responseBodyPos < responseBodySize; ++responseBodyPos)
  {
    auto c = responseBody[responseBodyPos];
    if (c < '0' || c > '9')
    {
      break;
    }

    expiresInSeconds = (expiresInSeconds * 10) + (static_cast<long long>(c) - '0');
  }

  // Return as "expires in <N> seconds"
  return std::chrono::seconds(expiresInSeconds);
}

std::string CustomManagedIdentityCredential::ParseAccessToken(std::string const& responseBody)
{
  // Locate 'access_token', and the subsequent ':' in the HTTP body JSON response.
  constexpr auto jsonAccessToken = "access_token";
  auto responseBodyPos = responseBody.find(':', responseBody.find(jsonAccessToken));
  if (responseBodyPos == std::string::npos)
  {
    // Not found - unexpected response format - throw.
    throw std::exception(jsonAccessToken);
  }

  // Locate the place where the token substring is in the body.
  auto const responseBodySize = responseBody.size();
  for (; responseBodyPos < responseBodySize; ++responseBodyPos)
  {
    auto c = responseBody[responseBodyPos];
    if (c != ':' && c != ' ' && c != '\"' && c != '\'')
    {
      break;
    }
  }

  // Locate the end of the token string.
  auto const tokenBegin = responseBodyPos;
  for (; responseBodyPos < responseBodySize; ++responseBodyPos)
  {
    auto c = responseBody[responseBodyPos];
    if (c == '\"' || c == '\'')
    {
      break;
    }
  }

  // Return the string between the two positions located - that would be our access token.
  auto const tokenEnd = responseBodyPos;
  auto const responseBodyBegin = responseBody.begin();
  return std::string(responseBodyBegin + tokenBegin, responseBodyBegin + tokenEnd);
}

// Now, some usage sample:
// Remember that the Managed Identity Credential only works on Azure VMs.

//#include <azure/storage/blobs/blob_client.hpp>
#include <iostream>

int main()
{
  {
    // Here, it is just a test for us to make sure that the credential does work.
    // Do not use it in your code. This is rather how AzureSDK client libraries will be using it.
    // You can compare the output to the output you'd get from Postman.
    // Token string should be matching, and the expiration should make sense.
    CustomManagedIdentityCredential credential;

    auto token
        = credential.GetToken({{"https://storage.azure.com/.default"}}, Azure::Core::Context());

    std::cout << "Token Expiration: " << token.ExpiresOn.ToString() << "\n\nToken: " << token.Token
              << "\n\n\n";
  }

  // And this is how it would get used in a real cutomer application:
  // CustomManagedIdentityCredential is accepted everywhere, where TokenCredential is accepted.
  // i.e. :
  //{
  // // Here, we create a blob client, supplying the Managed Identity Credential:
  //  auto blobClient = Azure::Storage::Blobs::BlobClient(
  //      "https://blob_url", std::make_shared<CustomManagedIdentityCredential>());
  //}
}
