#ifndef AES256GCM_VERIFIER_HPP
#define AES256GCM_VERIFIER_HPP

#include <openssl/evp.h>

#include <string>
#include <memory>

namespace aes256gcm
{

class verifier
{
public:
    /// @brief Creates a new AES256-GCM verification context.
    ///
    /// @param key Key used for decryption.
    /// @param nonce None used for encryption.
    /// @param tag Tag used to verify that decrytion was successful.
    /// @param additional_data Additional authenticated data.
    /// @throws A logic error is thrown on invalid key size.
    ///         An openssl_error is thrown on error of underlying OpenSSL function calls.
    verifier(
        std::string const & key,
        std::string const & nonce,
        std::string const & tag,
        std::string const & additional_data = {});
    
    ~verifier() = default;
    /// @brief Decrypts some data.
    ///
    /// @note input and output buffer are of equal size.
    ///
    /// @param in buffer containing the encrypted data.
    /// @param size size of input and output buffers.
    /// @throws An openssl_error is thrown on error of underlying OpenSSL function call.
    ///         A runtime_error is thrown on mismatch of output buffer size.
    void update(char const * in, size_t size);

    /// @brief Finalized the encrytion and checks if decryption was successful.
    ///
    /// @note All decrypted data is invalid, if the check was not successful.
    ///       The decrypted data should not be used in this case.
    ///
    /// @return true, if decryption was successful, false otherwise.
    bool finalize();

private:
    std::unique_ptr<EVP_CIPHER_CTX, void (*) (EVP_CIPHER_CTX*)> m_ctx;
};

}

#endif

