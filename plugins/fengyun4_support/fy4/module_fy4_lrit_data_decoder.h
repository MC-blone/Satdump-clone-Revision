#pragma once

#include "pipeline/modules/base/filestream_to_filestream.h"
#include "xrit/processor/xrit_channel_processor.h"
#include "xrit/xrit_file.h"

#include "fy4_des.h"

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace fy4
{
    namespace lrit
    {
        class FY4LRITDataDecoderModule :
            public satdump::pipeline::base::FileStreamToFileStreamModule
        {
        protected:
            std::string directory;
            std::string input_file_path;

            enum CustomFileParams
            {
                IS_ENCRYPTED,
                KEY_INDEX
            };

            std::map<
                std::string,
                std::shared_ptr<satdump::xrit::XRITChannelProcessor>
            > all_processors;

            std::mutex all_processors_mtx;

            std::map<
                uint16_t,
                std::vector<uint8_t>
            > decryption_keys;

            std::mutex decryption_keys_mtx;

            std::atomic<uint64_t> bytes_received;
            std::atomic<uint64_t> total_bytes;

            bool keys_loaded;

            bool loadEncryptionKeys();

            bool findEncryptionKey(
                uint16_t key_index,
                std::vector<uint8_t> &key);

            bool decryptLRITFile(
                satdump::xrit::XRITFile &file,
                uint16_t key_index);

            void saveEncryptedFile(
                satdump::xrit::XRITFile &file);

            void saveLRITFile(
                satdump::xrit::XRITFile &file);

            void processLRITFile(
                satdump::xrit::XRITFile &file);

        public:
            FY4LRITDataDecoderModule(
                std::string input_file,
                std::string output_file_hint,
                nlohmann::json parameters);

            ~FY4LRITDataDecoderModule();

            void process();

            void drawUI(bool window);

        public:
            static std::string getID();

            virtual std::string getIDM()
            {
                return getID();
            }

            static nlohmann::json getParams()
            {
                return {};
            }

            static std::shared_ptr<ProcessingModule> getInstance(
                std::string input_file,
                std::string output_file_hint,
                nlohmann::json parameters);
        };
    }
}