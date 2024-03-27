#include <catch2/catch_test_macros.hpp>

#include "utils.hpp"
#include "ecdsa.hpp"

TEST_CASE("ECDSA sign")
{
	const EllipticCurve curve{
			BigNumber({ 3 }, Sign::MINUS),
			BigNumber({
					0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76,
					0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE,
					0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
			}),
			BigNumber({
					0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
			})
	};

	const BigPoint generator{ BigNumber({
			0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5,
			0x63,
			0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4,
			0xA1,
			0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
	}), BigNumber({
			0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C,
			0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6,
			0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
	}) };

	const EcDsa ecDsa(
			BigNumber({
					0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9,
					0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
			}),
			BigNumber({
					0x9E, 0x56, 0xF5, 0x09, 0x19, 0x67, 0x84, 0xD9, 0x63, 0xD1, 0xC0,
					0xA4, 0x01, 0x51, 0x0E, 0xE7, 0xAD, 0xA3, 0xDC, 0xC5, 0xDE, 0xE0,
					0x4B, 0x15, 0x4B, 0xF6, 0x1A, 0xF1, 0xD5, 0xA6, 0xDE, 0xCE
			}),
			generator,
			curve);
	const BigNumber private_key({ 0xDC, 0x51, 0xD3, 0x86, 0x6A, 0x15, 0xBA, 0xCD, 0xE3,
								  0x3D, 0x96, 0xF9, 0x92, 0xFC, 0xA9, 0x9D, 0xA7, 0xE6, 0xEF, 0x09, 0x34, 0xE7,
								  0x09, 0x75, 0x59, 0xC2, 0x7F, 0x16, 0x14, 0xC8, 0x8A, 0x7F });
	const auto public_key = curve.multiply_point(generator, private_key);
	const std::vector<unsigned char> message{ 'a', 'b', 'c'};
	const auto signature = ecDsa.sign(message, private_key);
	const auto rData = signature.r.data();
	const auto sData = signature.s.data();
	REQUIRE(hexStr(rData.begin(), rData.end()) == "cb28e0999b9c7715fd0a80d8e47a77079716cbbf917dd72e97566ea1c066957c");
	REQUIRE(hexStr(sData.begin(), sData.end()) == "86fa3bb4e26cad5bf90b7f81899256ce7594bb1ea0c89212748bff3b3d5b0315");
	REQUIRE(ecDsa.verify(message, signature, public_key));

}