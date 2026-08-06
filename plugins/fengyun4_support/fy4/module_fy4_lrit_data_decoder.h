#pragma once

#include "pipeline/modules/base/filestream_to_filestream.h"
#include "xrit/processor/xrit_channel_processor.h"
#include "xrit/xrit_file.h"
#include <atomic>

namespace fy4
{
    namespace lrit
    {
        class FY4LRITDataDecoderModule : public satdump::pipeline::base::FileStreamToFileStreamModule
        {
        protected:
            std::string directory;

            enum CustomFileParams
            {
                IS_ENCRYPTED,
                KEY_INDEX,
            };

            std::map<std::string, std::shared_ptr<satdump::xrit::XRITChannelProcessor>> all_processors;
            std::mutex all_processors_mtx;

            // DAT decryption related
            bool is_dat_file;
            char key_input[17];
            bool key_entered;
            std::vector<uint8_t> key_bytes;
            std::atomic<bool> should_stop{false};

            void processLRITFile(satdump::xrit::XRITFile &file);
            
            // DES decryption functions
            bool parse_key(const std::string& key_str, std::vector<uint8_t>& key_bytes);
            std::vector<uint8_t> decrypt_dat_file(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

        public:
            FY4LRITDataDecoderModule(std::string input_file, std::string output_file_hint, nlohmann::json parameters);
            ~FY4LRITDataDecoderModule();
            void process();
            void drawUI(bool window);

        public:
            static std::string getID();
            virtual std::string getIDM() { return getID(); };
            static nlohmann::json getParams() { return {}; }
            static std::shared_ptr<ProcessingModule> getInstance(std::string input_file, std::string output_file_hint, nlohmann::json parameters);
        };
    } // namespace lrit
} // namespace fy4
