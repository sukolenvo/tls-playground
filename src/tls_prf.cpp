#include <algorithm>
#include <string>

#include "hmac.hpp"
#include "tls_prf.hpp"


void prf_hash(const std::vector<unsigned char> &secret, const std::vector<unsigned char> &seed, auto hmac_func, std::vector<unsigned char> &out)
{
	size_t pos = 0;
	auto pre_hash = hmac_func(seed, secret);
	std::vector<unsigned char> buffer(pre_hash.size() + seed.size());
	while (pos < out.size())
	{
		std::copy(pre_hash.begin(), pre_hash.end(), buffer.begin());
		std::copy(seed.begin(), seed.end(), buffer.begin() + pre_hash.size());
		const auto out_chunk = hmac_func(buffer, secret);
		const auto copy = std::min(out.size() - pos, out_chunk.size());
		std::copy_n(out_chunk.begin(), copy, out.begin() + pos);
		pos += copy;
		pre_hash = hmac_func({ pre_hash.begin(), pre_hash.end() }, secret);
	}
}


void prf(const std::vector<unsigned char> &secret, const std::vector<unsigned char> &seed, std::vector<unsigned char> &out)
{
	prf_hash({secret.begin(), secret.begin() + secret.size() / 2 }, seed, &hmac_md5, out);
	std::vector<unsigned char> sha_out(out.size());
	prf_hash({ secret.begin() + secret.size() / 2, secret.end() }, seed, &hmac_sha1, sha_out);
	for (size_t i = 0; i < out.size(); ++i)
	{
		out[i] ^= sha_out.at(i);
	}
}

std::vector<unsigned char> compute_master_secret(
		const std::array<unsigned char, 48> &premaster_secret,
		const std::array<unsigned char, 32> &client_random,
		const std::array<unsigned char, 32> &server_random)
{
	const auto seed_prefix = std::string("master secret");
	std::vector<unsigned char> seed(seed_prefix.size() + client_random.size() + server_random.size());
	std::copy(seed_prefix.begin(), seed_prefix.end(), seed.begin());
	std::copy(client_random.begin(), client_random.end(), seed.begin() + seed_prefix.size());
	std::copy(server_random.begin(), server_random.end(), seed.begin() + seed_prefix.size() + client_random.size());
	std::vector<unsigned char> result(48);
	prf({ premaster_secret.begin(), premaster_secret.end() }, seed, result);
	return result;
}

std::vector<unsigned char> compute_key_expansion(const std::vector<unsigned char> &master_secret,
		const std::array<unsigned char, 32> &client_random, const std::array<unsigned char, 32> &server_random,
		size_t key_size)
{
	const auto seed_prefix = std::string("key expansion");
	std::vector<unsigned char> seed(seed_prefix.size() + server_random.size() + client_random.size());
	std::copy(seed_prefix.begin(), seed_prefix.end(), seed.begin());
	std::copy(server_random.begin(), server_random.end(), seed.begin() + seed_prefix.size());
	std::copy(client_random.begin(), client_random.end(), seed.begin() + seed_prefix.size() + server_random.size());
	std::vector<unsigned char> result(key_size);
	prf(master_secret , seed, result);
	return result;
}

std::vector<unsigned char> prf(
		const std::vector<unsigned char> &secret,
		const std::string &label,
		const std::vector<unsigned char> &seed,
		size_t length)
{
	std::vector<unsigned char> prefixed_seed(label.size() + seed.size());
	std::copy(label.begin(), label.end(), prefixed_seed.begin());
	std::copy(seed.begin(), seed.end(), prefixed_seed.begin() + label.size());
	std::vector<unsigned char> result(length);
	prf(secret, prefixed_seed, result);
	return result;

}
