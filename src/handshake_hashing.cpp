#include <algorithm>

#include "tls_prf.hpp"

#include "handshake_hashing.hpp"

void HandshakeHashing::append(const std::vector<unsigned char> &handshake_message)
{
    md5_hashing.append(handshake_message);
    sha1_hashing.append(handshake_message);
}

std::vector<unsigned char> HandshakeHashing::compute_finished_hash(
        const std::vector<unsigned char> &master_secret,
        const std::string &label) const
{
    const auto md5_hash = Md5Hashing(md5_hashing).close();
    const auto sha1_hash = Sha1Hashing(sha1_hashing).close();
    std::vector<unsigned char> seed(md5_hash.size() + sha1_hash.size());
    std::copy(md5_hash.begin(), md5_hash.end(), seed.begin());
    std::copy(sha1_hash.begin(), sha1_hash.end(), seed.begin() + md5_hash.size());

    return prf(master_secret, label, seed, 12);
}