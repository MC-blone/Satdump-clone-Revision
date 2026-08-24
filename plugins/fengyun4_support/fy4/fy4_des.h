#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fy4
{
    namespace lrit
    {
        class FY4DES
        {
        public:
            FY4DES();

            void setKey(const uint8_t key[8]);

            std::vector<uint8_t> decryptECB(
                const uint8_t *data,
                size_t size);

            std::vector<uint8_t> decryptECB(
                const std::vector<uint8_t> &data);

        private:
            uint64_t subkeys[16];

            static uint64_t permute(
                uint64_t value,
                const int *table,
                int tableSize,
                int inputBits);

            static uint64_t bytesToU64(
                const uint8_t *data);

            static void u64ToBytes(
                uint64_t value,
                uint8_t *data);

            static uint32_t feistel(
                uint32_t right,
                uint64_t subkey);

            static uint64_t decryptBlock(
                uint64_t block,
                const uint64_t *subkeys);
        };
    }
}