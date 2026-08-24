#include "fy4_des.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace fy4
{
    namespace lrit
    {
        namespace
        {
            static const uint8_t S_BOXES[8][4][16] =
            {
                {
                    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
                },

                {
                    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
                },

                {
                    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
                },

                {
                    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
                },

                {
                    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
                },

                {
                    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                    {4,3,2,12,9,5,10,7,6,0,8,13,14,1,11,5}
                },

                {
                    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
                },

                {
                    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
                }
            };

            static const int IP[64] =
            {
                58,50,42,34,26,18,10,2,
                60,52,44,36,28,20,12,4,
                62,54,46,38,30,22,14,6,
                64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1,
                59,51,43,35,27,19,11,3,
                61,53,45,37,29,21,13,5,
                63,55,47,39,31,23,15,7
            };

            static const int FP[64] =
            {
                40,8,48,16,56,24,64,32,
                39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30,
                37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,
                35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26,
                33,1,41,9,49,17,57,25
            };

            static const int E[48] =
            {
                32,1,2,3,4,5,
                4,5,6,7,8,9,
                8,9,10,11,12,13,
                12,13,14,15,16,17,
                16,17,18,19,20,21,
                20,21,22,23,24,25,
                24,25,26,27,28,29,
                28,29,30,31,32,1
            };

            static const int P[32] =
            {
                16,7,20,21,
                29,12,28,17,
                1,15,23,26,
                5,18,31,10,
                2,8,24,14,
                32,27,3,9,
                19,13,30,6,
                22,11,4,25
            };

            static const int PC1[56] =
            {
                57,49,41,33,25,17,9,
                1,58,50,42,34,26,18,
                10,2,59,51,43,35,27,
                19,11,3,60,52,44,36,
                63,55,47,39,31,23,15,
                7,62,54,46,38,30,22,
                14,6,61,53,45,37,29,
                21,13,5,28,20,12,4
            };

            static const int PC2[48] =
            {
                14,17,11,24,1,5,
                3,28,15,6,21,10,
                23,19,12,4,26,8,
                16,7,27,20,13,2,
                41,52,31,37,47,55,
                30,40,51,45,33,48,
                44,49,39,56,34,53,
                46,42,50,36,29,32
            };

            static const int SHIFTS[16] =
            {
                1,1,2,2,2,2,2,2,
                1,2,2,2,2,2,2,1
            };
        }

        FY4DES::FY4DES()
        {
            std::memset(subkeys, 0, sizeof(subkeys));
        }

        uint64_t FY4DES::permute(
            uint64_t value,
            const int *table,
            int tableSize,
            int inputBits)
        {
            uint64_t result = 0;

            for (int i = 0; i < tableSize; i++)
            {
                result <<= 1;

                int bit = inputBits - table[i];

                result |= (value >> bit) & 1ULL;
            }

            return result;
        }

        uint64_t FY4DES::bytesToU64(const uint8_t *data)
        {
            uint64_t value = 0;

            for (int i = 0; i < 8; i++)
                value = (value << 8) | data[i];

            return value;
        }

        void FY4DES::u64ToBytes(
            uint64_t value,
            uint8_t *data)
        {
            for (int i = 7; i >= 0; i--)
            {
                data[i] = static_cast<uint8_t>(value & 0xff);
                value >>= 8;
            }
        }

        void FY4DES::setKey(const uint8_t key[8])
        {
            uint64_t key64 = 0;

            for (int i = 0; i < 8; i++)
                key64 = (key64 << 8) | key[i];

            uint64_t key56 =
                permute(key64, PC1, 56, 64);

            uint32_t c =
                static_cast<uint32_t>((key56 >> 28) & 0x0fffffff);

            uint32_t d =
                static_cast<uint32_t>(key56 & 0x0fffffff);

            for (int i = 0; i < 16; i++)
            {
                int shift = SHIFTS[i];

                c =
                    ((c << shift) & 0x0fffffff) |
                    (c >> (28 - shift));

                d =
                    ((d << shift) & 0x0fffffff) |
                    (d >> (28 - shift));

                uint64_t combined =
                    (static_cast<uint64_t>(c) << 28) | d;

                subkeys[i] =
                    permute(combined, PC2, 48, 56);
            }
        }

        uint32_t FY4DES::feistel(
            uint32_t right,
            uint64_t subkey)
        {
            uint64_t expanded =
                permute(
                    static_cast<uint64_t>(right),
                    E,
                    48,
                    32);

            uint64_t mixed = expanded ^ subkey;

            uint32_t result = 0;

            for (int i = 0; i < 8; i++)
            {
                int shift = 42 - i * 6;

                uint8_t chunk =
                    static_cast<uint8_t>(
                        (mixed >> shift) & 0x3f);

                uint8_t row =
                    static_cast<uint8_t>(
                        ((chunk & 0x20) >> 4) |
                        (chunk & 0x01));

                uint8_t column =
                    static_cast<uint8_t>(
                        (chunk >> 1) & 0x0f);

                result =
                    (result << 4) |
                    S_BOXES[i][row][column];
            }

            return static_cast<uint32_t>(
                permute(result, P, 32, 32));
        }

        uint64_t FY4DES::decryptBlock(
            uint64_t block,
            const uint64_t *subkeys)
        {
            block = permute(block, IP, 64, 64);

            uint32_t left =
                static_cast<uint32_t>(block >> 32);

            uint32_t right =
                static_cast<uint32_t>(block & 0xffffffff);

            for (int i = 15; i >= 0; i--)
            {
                uint32_t newLeft = right;

                uint32_t newRight =
                    left ^ feistel(right, subkeys[i]);

                left = newLeft;
                right = newRight;
            }

            uint64_t combined =
                (static_cast<uint64_t>(right) << 32) |
                left;

            return permute(combined, FP, 64, 64);
        }

        std::vector<uint8_t> FY4DES::decryptECB(
            const uint8_t *data,
            size_t size)
        {
            if (data == nullptr || size == 0)
                return {};

            size_t paddedSize =
                ((size + 7) / 8) * 8;

            std::vector<uint8_t> output(paddedSize, 0);

            std::memcpy(
                output.data(),
                data,
                size);

            size_t blocks = paddedSize / 8;

            for (size_t i = 0; i < blocks; i++)
            {
                uint64_t block =
                    bytesToU64(
                        output.data() + i * 8);

                uint64_t decrypted =
                    decryptBlock(
                        block,
                        subkeys);

                u64ToBytes(
                    decrypted,
                    output.data() + i * 8);
            }

            return output;
        }

        std::vector<uint8_t> FY4DES::decryptECB(
            const std::vector<uint8_t> &data)
        {
            return decryptECB(
                data.data(),
                data.size());
        }
    }
}