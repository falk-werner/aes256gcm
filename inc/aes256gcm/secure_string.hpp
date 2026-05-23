#ifndef AES256GCM_SECURE_STRING_HPP
#define AES256GCM_SECURE_STRING_HPP

#include <cstddef>

namespace aes256gcm
{

/// @brief Secure String
///
/// A security string is intended to keep sensitive data.
/// It will securely erase the data on destruction to ensure
/// that no fragements of sensitive data is kept in memory.
class secure_string
{
public:

    /// @brief Creates an empty instance intended for later assignment.
    secure_string();

    /// @brief Create an instance of secure string from a C string.
    ///
    /// @note The contents of the C string are securely erased.
    ///
    /// @param value C string used to initialize the secure string.
    explicit secure_string(char * value);

    /// @brief Creates an instance of secure string from a buffer.
    ///
    /// @note The contents of the buffer are securely erased.
    ///
    /// @param value Buffer used to initialize the secure string.
    /// @param size Size of the buffer.
    secure_string(char * value, size_t size);

    /// @brief Destructs the secure string.
    ///
    /// All stored data are erase securely.
    ~secure_string();

    /// @brief Constructs a secure string from an existing one.
    ///
    /// @param other Reference of prototype used to initialize the secure string.
    secure_string(secure_string const & other);

    /// @brief Assigns the value of an existing secure string.
    /// @param other Reference to the secure string used for assignment.
    /// @return Self-Reference.
    secure_string& operator=(secure_string const & other);

    /// @brief Creates a new secure string by moving the contents of an existing one.
    ///
    /// After the operation, the other secure string will be empty.
    ///
    /// @param other Reference to secure string used to move data from.
    secure_string(secure_string && other);

    /// @brief Move the contents of another secure string to this one.
    ///
    /// The former contents of this secure string are securely erased.
    /// After the operation, the other secure string will be empty.
    ///
    /// @param other Reference to secure string used to move data from.
    /// @return Self-Reference.
    secure_string& operator=(secure_string && other);

    /// @brief Equality operator.
    ///
    /// @param other Secure string to compare with.
    /// @return True if the size and contents of this and the other secure string matches.
    bool operator==(secure_string const & other) const;

    /// @brief Unequality operator.
    /// @param other Secure string to compare with.
    /// @return True if either the sizes or the contents of this and the other secure string do not match.
    bool operator!=(secure_string const & other) const;

    /// @brief Assigns the value of from an existing C string.
    ///
    /// The former contents of this secure string are securely erased.
    /// The contents of the C string are securely erased.
    ///
    /// @param value C string assigned to the secure string.
    /// @return Self-Reference.
    secure_string& operator=(char * value);

    /// @brief Returns a pointer to the contents of the secure string.
    /// @return Pointer to the contents of the secure string.
    char const * c_str() const;

    /// @brief Returns the size of the secure string.
    /// @return Size of the secure string.
    size_t size() const;

    /// @brief Securely clears the contents of the secure string.
    void clear();

private:
    size_t size_;
    char * value_;
};

}

#endif