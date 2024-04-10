#ifndef TLS_PLAYGROUND_CIPHER_SUITE_HPP
#define TLS_PLAYGROUND_CIPHER_SUITE_HPP

#include <array>

#include "tls_record_mac.hpp"

class CipherSuite
{
public:
	virtual void encrypt(TlsRecord &tlsRecord) = 0;
	virtual void decrypt(TlsRecord &tlsRecord) = 0;

	virtual ~CipherSuite() = default;
};

class NullCipherSuite : public CipherSuite
{
public:
	void encrypt(TlsRecord &) override
	{
	};

	void decrypt(TlsRecord &) override
	{

	};

	~NullCipherSuite() override = default;
};

class Aes128CipherSuite : public CipherSuite
{
	std::array<unsigned char, 16> iv;
	std::array<unsigned char, 16> key;
public:
	Aes128CipherSuite(const std::array<unsigned char, 16> &iv, const std::array<unsigned char, 16> &key);

	~Aes128CipherSuite() override = default;

	void encrypt(TlsRecord &tls_record) override;

	void decrypt(TlsRecord &tls_record) override;
};

#endif //TLS_PLAYGROUND_CIPHER_SUITE_HPP
