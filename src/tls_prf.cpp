#include <algorithm>

#include "hmac.hpp"
#include "tls_prf.hpp"

std::vector<unsigned char> prf(const std::vector<unsigned char> &secret, const std::vector<unsigned char> &seed)
{
	const auto a1_md5 = hmac_md5(seed, secret);
	const auto a2_md5 = hmac_md5({ a1_md5.begin(), a1_md5.end() }, secret);
	const auto a3_md5 = hmac_md5({ a2_md5.begin(), a2_md5.end() }, secret);
	std::vector<unsigned char> md5_input(a1_md5.size() + seed.size());
	std::copy(a1_md5.begin(), a1_md5.end(), md5_input.begin());
	std::copy(seed.begin(), seed.end(), md5_input.begin() + a1_md5.size());
	const auto p1_md5 = hmac_md5(md5_input, secret);
	std::copy(a2_md5.begin(), a2_md5.end(), md5_input.begin());
	std::copy(seed.begin(), seed.end(), md5_input.begin() + a2_md5.size());
	const auto p2_md5 = hmac_md5(md5_input, secret);
	std::copy(a3_md5.begin(), a3_md5.end(), md5_input.begin());
	std::copy(seed.begin(), seed.end(), md5_input.begin() + a3_md5.size());
	const auto p3_md5 = hmac_md5(md5_input, secret);
	std::vector<unsigned char> md5_result(40);
	std::copy(p1_md5.begin(), p1_md5.end(), md5_result.begin());
	std::copy(p2_md5.begin(), p2_md5.end(), md5_result.begin() + p1_md5.size());
	std::copy_n(p3_md5.begin(), md5_result.size() - p1_md5.size() * 2, md5_result.begin() + p1_md5.size() * 2);

	const auto a1_sha = hmac_sha256(seed, secret);
	const auto a2_sha = hmac_sha256({ a1_sha.begin(), a1_sha.end() }, secret);
	std::vector<unsigned char> sha_input(a1_sha.size() + seed.size());
	std::copy(a1_sha.begin(), a1_sha.end(), sha_input.begin());
	std::copy(seed.begin(), seed.end(), sha_input.begin() + a1_sha.size());
	const auto p1_sha = hmac_sha256(sha_input, secret);
	std::copy(a2_sha.begin(), a2_sha.end(), sha_input.begin());
	std::copy(seed.begin(), seed.end(), sha_input.begin() + a2_sha.size());
	const auto p2_sha = hmac_sha256(sha_input, secret);
	std::vector<unsigned char> sha_result(40);
	std::copy(p1_sha.begin(), p1_sha.end(), sha_result.begin());
	std::copy(p2_sha.begin(), p2_sha.end(), sha_result.begin() + p1_sha.size());
	for (size_t i = 0; i < md5_result.size(); ++i)
	{
		md5_result[i] ^= sha_result.at(i);
	}
	return md5_result;
}
