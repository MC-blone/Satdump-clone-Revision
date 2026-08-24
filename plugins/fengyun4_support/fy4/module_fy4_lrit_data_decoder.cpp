#include "module_fy4_lrit_data_decoder.h"

#include "common/utils.h"
#include "core/resources.h"
#include "imgui/imgui.h"
#include "imgui/imgui_image.h"
#include "logger.h"
#include "xrit/fy4/fy4_headers.h"
#include "xrit/processor/xrit_channel_processor_render.h"
#include "xrit/transport/xrit_demux.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace fy4
{
    namespace lrit
    {
        namespace
        {
            static std::string makeHex(
                const std::vector<uint8_t> &data)
            {
                std::ostringstream ss;

                ss << std::hex
                   << std::setfill('0');

                for (size_t i = 0; i < data.size(); i++)
                {
                    ss << std::setw(2)
                       << static_cast<int>(data[i]);
                }

                return ss.str();
            }

            static bool readFile(
                const std::string &path,
                std::vector<uint8_t> &data)
            {
                std::ifstream file(
                    path,
                    std::ios::binary);

                if (!file)
                    return false;

                file.seekg(
                    0,
                    std::ios::end);

                std::streamoff size =
                    file.tellg();

                if (size <= 0)
                    return false;

                file.seekg(
                    0,
                    std::ios::beg);

                data.resize(
                    static_cast<size_t>(size));

                file.read(
                    reinterpret_cast<char *>(data.data()),
                    size);

                return file.good() ||
                       file.eof();
            }

            static bool writeFile(
                const std::string &path,
                const std::vector<uint8_t> &data)
            {
                std::ofstream file(
                    path,
                    std::ios::binary);

                if (!file)
                    return false;

                if (!data.empty())
                {
                    file.write(
                        reinterpret_cast<const char *>(data.data()),
                        static_cast<std::streamsize>(data.size()));
                }

                return file.good();
            }

            static bool writeFile(
                const std::string &path,
                const uint8_t *data,
                size_t size)
            {
                std::ofstream file(
                    path,
                    std::ios::binary);

                if (!file)
                    return false;

                if (data != nullptr && size > 0)
                {
                    file.write(
                        reinterpret_cast<const char *>(data),
                        static_cast<std::streamsize>(size));
                }

                return file.good();
            }

            static void createDirectory(
                const std::string &path)
            {
                try
                {
                    std::filesystem::create_directories(path);
                }
                catch (...)
                {
                }
            }
        }

        FY4LRITDataDecoderModule::FY4LRITDataDecoderModule(
            std::string input_file,
            std::string output_file_hint,
            nlohmann::json parameters)
            : satdump::pipeline::base::FileStreamToFileStreamModule(
                  input_file,
                  output_file_hint,
                  parameters),
              input_file_path(input_file),
              bytes_received(0),
              total_bytes(0),
              keys_loaded(false)
        {
            fsfsm_enable_output = false;

            try
            {
                if (std::filesystem::exists(input_file_path))
                {
                    total_bytes =
                        static_cast<uint64_t>(
                            std::filesystem::file_size(
                                input_file_path));
                }
            }
            catch (...)
            {
                total_bytes = 0;
            }
        }

        FY4LRITDataDecoderModule::~FY4LRITDataDecoderModule()
        {
        }

        bool FY4LRITDataDecoderModule::loadEncryptionKeys()
        {
            std::vector<std::string> paths;

            try
            {
                std::string p =
                    resources::getResourcePath(
                        "fy4/EncryptionKeyMessage.bin");

                if (!p.empty())
                    paths.push_back(p);
            }
            catch (...)
            {
            }

            paths.push_back(
                "files/resources/fy4/EncryptionKeyMessage.bin");

            paths.push_back(
                "./files/resources/fy4/EncryptionKeyMessage.bin");

            paths.push_back(
                "../files/resources/fy4/EncryptionKeyMessage.bin");

            paths.push_back(
                "../resources/fy4/EncryptionKeyMessage.bin");

            std::string key_path;

            for (size_t i = 0; i < paths.size(); i++)
            {
                try
                {
                    if (std::filesystem::exists(paths[i]) &&
                        std::filesystem::is_regular_file(paths[i]))
                    {
                        key_path = paths[i];
                        break;
                    }
                }
                catch (...)
                {
                }
            }

            if (key_path.empty())
            {
                logger->warning(
                    "FY-4 EncryptionKeyMessage.bin was not found. "
                    "Encrypted LRIT files will be preserved but not decrypted.");

                keys_loaded = false;
                return false;
            }

            std::vector<uint8_t> data;

            if (!readFile(key_path, data))
            {
                logger->warning(
                    "Unable to read FY-4 encryption key file: " +
                    key_path);

                keys_loaded = false;
                return false;
            }

            if (data.size() < 2)
            {
                logger->warning(
                    "FY-4 encryption key file is too small: " +
                    key_path);

                keys_loaded = false;
                return false;
            }

            /*
             * EncryptionKeyMessage.bin format:
             *
             * uint16 BE key_count
             *
             * repeated:
             *   uint16 BE key_index
             *   uint64 BE DES key
             */

            uint16_t key_count =
                static_cast<uint16_t>(
                    (static_cast<uint16_t>(data[0]) << 8) |
                    static_cast<uint16_t>(data[1]));

            size_t offset = 2;

            size_t required =
                2 + static_cast<size_t>(key_count) * 10;

            if (data.size() < required)
            {
                logger->warning(
                    "FY-4 encryption key file is truncated. "
                    "Expected at least " +
                    std::to_string(required) +
                    " bytes, got " +
                    std::to_string(data.size()));

                keys_loaded = false;
                return false;
            }

            std::map<uint16_t, std::vector<uint8_t>> new_keys;

            for (uint16_t i = 0; i < key_count; i++)
            {
                uint16_t index =
                    static_cast<uint16_t>(
                        (static_cast<uint16_t>(data[offset]) << 8) |
                        static_cast<uint16_t>(data[offset + 1]));

                offset += 2;

                std::vector<uint8_t> key(8);

                for (int j = 0; j < 8; j++)
                    key[j] = data[offset + j];

                offset += 8;

                new_keys[index] = key;
            }

            {
                std::lock_guard<std::mutex> lock(
                    decryption_keys_mtx);

                decryption_keys.swap(
                    new_keys);
            }

            keys_loaded = !decryption_keys.empty();

            if (keys_loaded)
            {
                logger->info(
                    "Loaded " +
                    std::to_string(decryption_keys.size()) +
                    " FY-4 decryption keys from " +
                    key_path);
            }
            else
            {
                logger->warning(
                    "FY-4 encryption key file contains no usable keys.");
            }

            return keys_loaded;
        }

        bool FY4LRITDataDecoderModule::findEncryptionKey(
            uint16_t key_index,
            std::vector<uint8_t> &key)
        {
            std::lock_guard<std::mutex> lock(
                decryption_keys_mtx);

            auto it =
                decryption_keys.find(key_index);

            if (it == decryption_keys.end())
                return false;

            if (it->second.size() != 8)
                return false;

            key = it->second;

            return true;
        }

        bool FY4LRITDataDecoderModule::decryptLRITFile(
            satdump::xrit::XRITFile &file,
            uint16_t key_index)
        {
            std::vector<uint8_t> key;

            if (!findEncryptionKey(
                    key_index,
                    key))
            {
                logger->warning(
                    "No FY-4 DES key found for key index " +
                    std::to_string(key_index) +
                    ". Keeping encrypted file.");

                return false;
            }

            if (file.lrit_data.empty())
            {
                logger->warning(
                    "Encrypted FY-4 LRIT file contains no data: " +
                    file.filename);

                return false;
            }

            FY4DES des;

            des.setKey(
                key.data());

            try
            {
                std::vector<uint8_t> decrypted =
                    des.decryptECB(
                        file.lrit_data);

                file.lrit_data.swap(
                    decrypted);

                logger->info(
                    "FY-4 LRIT decrypted: " +
                    file.filename +
                    " key=" +
                    std::to_string(key_index) +
                    " DES=" +
                    makeHex(key));

                file.custom_flags.insert_or_assign(
                    IS_ENCRYPTED,
                    false);

                return true;
            }
            catch (const std::exception &e)
            {
                logger->error(
                    "FY-4 DES decryption failed for " +
                    file.filename +
                    ": " +
                    std::string(e.what()));

                return false;
            }
        }

        void FY4LRITDataDecoderModule::saveEncryptedFile(
            satdump::xrit::XRITFile &file)
        {
            std::string path =
                directory +
                "/LRIT_ENCRYPTED";

            createDirectory(path);

            std::string output =
                path +
                "/" +
                file.filename;

            logger->info(
                "Writing encrypted FY-4 LRIT file " +
                output);

            if (!writeFile(
                    output,
                    file.lrit_data))
            {
                logger->error(
                    "Unable to write encrypted LRIT file: " +
                    output);
            }
        }

        void FY4LRITDataDecoderModule::saveLRITFile(
            satdump::xrit::XRITFile &file)
        {
            std::string path =
                directory +
                "/LRIT";

            createDirectory(path);

            std::string output =
                path +
                "/" +
                file.filename;

            logger->info(
                "Writing decoded FY-4 LRIT file " +
                output);

            if (!writeFile(
                    output,
                    file.lrit_data))
            {
                logger->error(
                    "Unable to write LRIT file: " +
                    output);
            }
        }

        void FY4LRITDataDecoderModule::processLRITFile(
            satdump::xrit::XRITFile &file)
        {
            satdump::xrit::PrimaryHeader primary_header =
                file.getHeader<satdump::xrit::PrimaryHeader>();

            bool encrypted = false;
            uint16_t key_index = 0;

            if (file.custom_flags.count(IS_ENCRYPTED))
            {
                encrypted =
                    file.custom_flags[IS_ENCRYPTED];
            }

            if (file.custom_flags.count(KEY_INDEX))
            {
                key_index =
                    static_cast<uint16_t>(
                        file.custom_flags[KEY_INDEX]);
            }

            /*
             * 永远先保存收到的原始加密文件。
             */
            if (encrypted)
            {
                saveEncryptedFile(file);

                /*
                 * 没有密钥时严格跳过解密。
                 */
                if (!keys_loaded)
                {
                    return;
                }

                /*
                 * 找不到对应 key 时也不继续。
                 */
                if (!decryptLRITFile(
                        file,
                        key_index))
                {
                    return;
                }

                /*
                 * 解密后的 LRIT 数据保存。
                 */
                saveLRITFile(file);
            }

            /*
             * 非图像数据直接保存。
             */
            if (primary_header.file_type_code != 0 ||
                !file.hasHeader<
                    satdump::xrit::fy4::ImageInformationRecord>())
            {
                if (!encrypted)
                    saveLRITFile(file);

                return;
            }

            satdump::xrit::XRITFileInfo finfo =
                satdump::xrit::identifyXRITFIle(file);

            if (finfo.type !=
                satdump::xrit::XRIT_UNKNOWN)
            {
                std::string processor_name =
                    finfo.satellite_short_name;

                {
                    std::lock_guard<std::mutex> lock(
                        all_processors_mtx);

                    if (all_processors.count(
                            processor_name) == 0)
                    {
                        auto p =
                            std::make_shared<
                                satdump::xrit::XRITChannelProcessor>();

                        size_t slash =
                            d_output_file_hint.rfind('/');

                        if (slash != std::string::npos)
                        {
                            p->directory =
                                d_output_file_hint.substr(
                                    0,
                                    slash) +
                                "/IMAGES";
                        }
                        else
                        {
                            p->directory =
                                directory +
                                "/IMAGES";
                        }

                        all_processors.emplace(
                            processor_name,
                            p);
                    }
                }

                std::shared_ptr<
                    satdump::xrit::XRITChannelProcessor> processor;

                {
                    std::lock_guard<std::mutex> lock(
                        all_processors_mtx);

                    processor =
                        all_processors[processor_name];
                }

                processor->push(
                    finfo,
                    file);
            }
            else
            {
                /*
                 * 识别不了的 XRIT 数据仍然保存。
                 */
                if (!encrypted)
                    saveLRITFile(file);
            }
        }

        void FY4LRITDataDecoderModule::process()
        {
            directory =
                d_output_file_hint;

            size_t slash =
                directory.rfind('/');

            if (slash != std::string::npos)
                directory =
                    directory.substr(0, slash);

            if (directory.empty())
                directory = ".";

            createDirectory(directory);

            createDirectory(
                directory + "/LRIT");

            createDirectory(
                directory + "/LRIT_ENCRYPTED");

            createDirectory(
                directory + "/IMAGES");

            bytes_received = 0;

            total_bytes = 0;

            try
            {
                if (std::filesystem::exists(
                        input_file_path))
                {
                    total_bytes =
                        static_cast<uint64_t>(
                            std::filesystem::file_size(
                                input_file_path));
                }
            }
            catch (...)
            {
            }

            /*
             * 尝试加载 FY-4 密钥。
             *
             * 找不到不会让模块失败。
             */
            loadEncryptionKeys();

            logger->info(
                "Demultiplexing and deframing FY-4 LRIT...");

            satdump::xrit::XRITDemux lrit_demux(
                1012,
                false);

            lrit_demux.onParseHeader =
                [this](satdump::xrit::XRITFile &file) -> void
            {
                if (file.hasHeader<
                        satdump::xrit::fy4::ImageInformationRecord>())
                {
                    satdump::xrit::fy4::ImageInformationRecord
                        image_structure_record =
                            file.getHeader<
                                satdump::xrit::fy4::ImageInformationRecord>();

                    logger->debug(
                        "FY-4 image data: " +
                        std::to_string(
                            image_structure_record.columns_count) +
                        "x" +
                        std::to_string(
                            image_structure_record.lines_count));
                }

                if (file.hasHeader<
                        satdump::xrit::fy4::KeyHeader>())
                {
                    satdump::xrit::fy4::KeyHeader key_header =
                        file.getHeader<
                            satdump::xrit::fy4::KeyHeader>();

                    if (key_header.key != 0)
                    {
                        file.custom_flags.insert_or_assign(
                            IS_ENCRYPTED,
                            true);

                        file.custom_flags.insert_or_assign(
                            KEY_INDEX,
                            static_cast<int>(
                                key_header.key));

                        logger->debug(
                            "FY-4 encrypted LRIT, key index=" +
                            std::to_string(key_header.key));
                    }
                    else
                    {
                        file.custom_flags.insert_or_assign(
                            IS_ENCRYPTED,
                            false);
                    }
                }
                else
                {
                    file.custom_flags.insert_or_assign(
                        IS_ENCRYPTED,
                        false);
                }
            };

            uint8_t cadu[1024];

            while (should_run())
            {
                read_data(
                    cadu,
                    sizeof(cadu));

                bytes_received +=
                    sizeof(cadu);

                if (total_bytes > 0 &&
                    bytes_received > total_bytes)
                {
                    bytes_received =
                        total_bytes;
                }

                std::vector<
                    satdump::xrit::XRITFile> files =
                    lrit_demux.work(cadu);

                for (auto &file : files)
                    processLRITFile(file);
            }

            cleanup();

            for (auto &p : all_processors)
                p.second->flush();
        }

        void FY4LRITDataDecoderModule::drawUI(
            bool window)
        {
            ImGui::Begin(
                "FY-4x LRIT Data Decoder",
                NULL,
                window ? 0 : NOWINDOW_FLAGS);

            uint64_t current =
                bytes_received.load();

            uint64_t total =
                total_bytes.load();

            if (total > 0)
            {
                double progress =
                    static_cast<double>(current) /
                    static_cast<double>(total);

                if (progress > 1.0)
                    progress = 1.0;

                if (progress < 0.0)
                    progress = 0.0;

                ImGui::ProgressBar(
                    static_cast<float>(progress),
                    ImVec2(-1, 0),
                    NULL);

                ImGui::Text(
                    "%.2f%%",
                    progress * 100.0);

                ImGui::Text(
                    "Received: %llu / %llu bytes",
                    static_cast<unsigned long long>(current),
                    static_cast<unsigned long long>(total));
            }
            else
            {
                ImGui::Text(
                    "Received: %llu bytes",
                    static_cast<unsigned long long>(current));
            }

            ImGui::Separator();

            {
                std::lock_guard<std::mutex> lock(
                    all_processors_mtx);

                satdump::xrit::renderAllTabsFromProcessors(
                    all_processors);
            }

            drawProgressBar();

            ImGui::End();
        }

        std::string FY4LRITDataDecoderModule::getID()
        {
            return "fy4_lrit_data_decoder";
        }

        std::shared_ptr<
            satdump::pipeline::ProcessingModule>
        FY4LRITDataDecoderModule::getInstance(
            std::string input_file,
            std::string output_file_hint,
            nlohmann::json parameters)
        {
            return std::make_shared<
                FY4LRITDataDecoderModule>(
                    input_file,
                    output_file_hint,
                    parameters);
        }
    }
}