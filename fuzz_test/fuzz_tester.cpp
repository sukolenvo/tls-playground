#include <algorithm>
#include <array>
#include <vector>

#include <aes.hpp>
#include <md5.hpp>
#include <sha.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const std::vector<unsigned char> input{data, data + size };

  md5_hash(input);
  sha256_hash(input);
  Sha1Hashing sha1{};
  sha1.append(input);
  sha1.close();

  std::array<unsigned char, 16> aes_key{};
  std::array<unsigned char, 16> aes_iv{};
  std::vector<unsigned char> aes_input{data, data + size / 16 * 16};
  std::copy_n(data, std::min(aes_key.size(), size), aes_key.begin());
  if (size > aes_key.size()) {
      std::copy_n(data + aes_key.size(), std::min(aes_iv.size(), size - aes_key.size()), aes_iv.begin());
  }
  const auto cipher = aes128_cbc_encrypt(aes_input, aes_iv, aes_key);
  const auto decrypted = aes128_cbc_decrypt(cipher, aes_iv, aes_key);
  return aes_input == decrypted ? 0 : 1;
}