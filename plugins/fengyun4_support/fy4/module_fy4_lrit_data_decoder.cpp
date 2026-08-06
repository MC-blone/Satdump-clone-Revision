#include "module_fy4_lrit_data_decoder.h"
#include "common/utils.h"
#include "core/resources.h"
#include "image/io.h"
#include "imgui/imgui.h"
#include "imgui/imgui_image.h"
#include "logger.h"
#include "xrit/fy4/fy4_headers.h"
#include "xrit/processor/xrit_channel_processor_render.h"
#include "xrit/transport/xrit_demux.h"
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <vector>

namespace fy4
{
    namespace lrit
    {
        // DES S-boxes
        static const int S_BOXES[8][4][16] = {
            {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
             {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
             {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
             {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
            {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
             {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
             {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
             {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
            {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
             {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
             {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
             {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
            {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
             {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
             {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
             {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
            {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
             {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
             {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
             {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
            {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
             {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
             {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
             {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
            {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
             {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
             {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
             {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
            {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
             {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
             {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
             {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
        };

        // Permutation tables
        static const int IP[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
        static const int FP[64] = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
        static const int E[48] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
        static const int P[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
        static const int PC1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
        static const int PC2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
        static const int SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

        static uint64_t permute_bits(uint64_t value, const int* table, int input_bits) {
            uint64_t result = 0;
            for (int i = 0; i < 64 && table[i] > 0; i++) {
                result = (result << 1) | ((value >> (input_bits - table[i])) & 1);
            }
            return result;
        }

        static std::vector<uint64_t> build_subkeys(uint64_t key) {
            uint64_t key56 = permute_bits(key, PC1, 64);
            
            uint32_t c = key56 >> 28;
            uint32_t d = key56 & 0x0FFFFFFF;
            
            std::vector<uint64_t> subkeys;
            for (int i = 0; i < 16; i++) {
                int shift = SHIFTS[i];
                c = ((c << shift) & 0x0FFFFFFF) | (c >> (28 - shift));
                d = ((d << shift) & 0x0FFFFFFF) | (d >> (28 - shift));
                uint64_t combined = ((uint64_t)c << 28) | d;
                subkeys.push_back(permute_bits(combined, PC2, 56));
            }
            return subkeys;
        }

        static uint64_t des_decrypt_block(uint64_t block, const std::vector<uint64_t>& subkeys) {
            block = permute_bits(block, IP, 64);
            
            uint32_t left = block >> 32;
            uint32_t right = block & 0xFFFFFFFF;
            
            for (int i = 15; i >= 0; i--) {
                uint64_t expanded = permute_bits(right, E, 32);
                uint64_t mixed = expanded ^ subkeys[i];
                
                uint32_t s_result = 0;
                for (int box_idx = 0; box_idx < 8; box_idx++) {
                    int shift = 42 - (box_idx * 6);
                    uint8_t chunk = (mixed >> shift) & 0x3F;
                    uint8_t row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
                    uint8_t col = (chunk >> 1) & 0x0F;
                    s_result = (s_result << 4) | S_BOXES[box_idx][row][col];
                }
                
                uint32_t p_result = permute_bits(s_result, P, 32);
                uint32_t new_left = right;
                right = left ^ p_result;
                left = new_left;
            }
            
            uint64_t combined = ((uint64_t)right << 32) | left;
            return permute_bits(combined, FP, 64);
        }

        static std::vector<uint8_t> des_ecb_decrypt(const std::vector<uint8_t>& data, const std::vector<uint64_t>& subkeys) {
            std::vector<uint8_t> result;
            size_t len = data.size();
            size_t padded_len = ((len + 7) / 8) * 8;
            
            for (size_t i = 0; i < padded_len; i += 8) {
                uint64_t block = 0;
                for (size_t j = 0; j < 8 && (i + j) < len; j++) {
                    block = (block << 8) | data[i + j];
                }
                // Pad with zeros if less than 8 bytes
                if (i + 8 > len) {
                    for (size_t j = len - i; j < 8; j++) {
                        block = (block << 8) | 0;
                    }
                }
                uint64_t decrypted = des_decrypt_block(block, subkeys);
                for (int j = 7; j >= 0; j--) {
                    result.push_back((decrypted >> (j * 8)) & 0xFF);
                }
            }
            return result;
        }

        FY4LRITDataDecoderModule::FY4LRITDataDecoderModule(std::string input_file, std::string output_file_hint, nlohmann::json parameters)
            : satdump::pipeline::base::FileStreamToFileStreamModule(input_file, output_file_hint, parameters)
        {
            fsfsm_enable_output = false;
            key_input[0] = '\0';
            key_entered = false;
            show_key_input = true;
            is_dat_file = false;
            
            // Detect if this is a DAT file
            std::string ext = input_file.substr(input_file.find_last_of('.') + 1);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == "dat") {
                is_dat_file = true;
                logger->info("DAT file detected, will attempt decryption if encrypted");
            }
        }

        FY4LRITDataDecoderModule::~FY4LRITDataDecoderModule()
        {
        }

        bool FY4LRITDataDecoderModule::parse_key(const std::string& key_str, std::vector<uint8_t>& key_bytes) {
            // Try to parse 16 hex characters
            if (key_str.length() == 16) {
                try {
                    key_bytes.clear();
                    for (size_t i = 0; i < 16; i += 2) {
                        std::string byte_str = key_str.substr(i, 2);
                        uint8_t byte = std::stoi(byte_str, nullptr, 16);
                        key_bytes.push_back(byte);
                    }
                    return key_bytes.size() == 8;
                } catch (...) {
                    return false;
                }
            }
            return false;
        }

        std::vector<uint8_t> FY4LRITDataDecoderModule::decrypt_dat_file(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
            if (data.size() < 16 || data[0] != 0) {
                logger->error("Invalid DAT file format");
                return {};
            }
            
            // Parse header
            uint16_t header_len = (data[1] << 8) | data[2];
            uint32_t total_header = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
            uint64_t data_bits = 0;
            for (int i = 0; i < 8; i++) {
                data_bits = (data_bits << 8) | data[8 + i];
            }
            
            logger->debug("Header length: " + std::to_string(header_len));
            logger->debug("Total header: " + std::to_string(total_header));
            logger->debug("Data bits: " + std::to_string(data_bits));
            
            // Extract encrypted data
            if (data.size() <= total_header) {
                logger->error("No encrypted data found");
                return {};
            }
            
            std::vector<uint8_t> encrypted_data(data.begin() + total_header, data.end());
            
            // Build subkeys
            uint64_t key64 = 0;
            for (int i = 0; i < 8; i++) {
                key64 = (key64 << 8) | key[i];
            }
            std::vector<uint64_t> subkeys = build_subkeys(key64);
            
            // Decrypt
            std::vector<uint8_t> decrypted = des_ecb_decrypt(encrypted_data, subkeys);
            
            // Trim to exact bit length
            size_t byte_len = (data_bits + 7) / 8;
            if (decrypted.size() > byte_len) {
                decrypted.resize(byte_len);
            }
            int remainder = data_bits % 8;
            if (remainder > 0 && !decrypted.empty()) {
                uint8_t mask = (0xFF << (8 - remainder)) & 0xFF;
                decrypted[decrypted.size() - 1] &= mask;
            }
            
            return decrypted;
        }

        void FY4LRITDataDecoderModule::process()
        {
            std::string directory = d_output_file_hint.substr(0, d_output_file_hint.rfind('/'));

            if (!std::filesystem::exists(directory))
                std::filesystem::create_directory(directory);

            this->directory = directory;

            // If this is a DAT file, handle decryption
            if (is_dat_file) {
                logger->info("Processing DAT file...");
                
                // Wait for user to enter key
                while (!key_entered && should_run()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                
                if (!should_run()) return;
                
                // Read DAT file
                std::ifstream file(d_input_file, std::ios::binary);
                if (!file.is_open()) {
                    logger->error("Failed to open DAT file: " + d_input_file);
                    return;
                }
                
                file.seekg(0, std::ios::end);
                size_t file_size = file.tellg();
                file.seekg(0, std::ios::beg);
                
                std::vector<uint8_t> dat_data(file_size);
                file.read((char*)dat_data.data(), file_size);
                file.close();
                
                // Attempt decryption
                std::vector<uint8_t> decrypted_data = decrypt_dat_file(dat_data, key_bytes);
                if (decrypted_data.empty()) {
                    logger->error("Decryption failed");
                    return;
                }
                
                logger->info("Decrypted " + std::to_string(decrypted_data.size()) + " bytes");
                
                // Look for JPEG or PNG signatures
                bool found_image = false;
                std::vector<uint8_t> image_data;
                
                // Look for JPEG
                for (size_t i = 0; i < decrypted_data.size() - 2; i++) {
                    if (decrypted_data[i] == 0xFF && decrypted_data[i+1] == 0xD8 && decrypted_data[i+2] == 0xFF) {
                        logger->info("Found JPEG signature at offset " + std::to_string(i));
                        image_data.assign(decrypted_data.begin() + i, decrypted_data.end());
                        found_image = true;
                        break;
                    }
                }
                
                // Look for PNG
                if (!found_image) {
                    for (size_t i = 0; i < decrypted_data.size() - 8; i++) {
                        if (decrypted_data[i] == 0x89 && decrypted_data[i+1] == 0x50 && 
                            decrypted_data[i+2] == 0x4E && decrypted_data[i+3] == 0x47 &&
                            decrypted_data[i+4] == 0x0D && decrypted_data[i+5] == 0x0A &&
                            decrypted_data[i+6] == 0x1A && decrypted_data[i+7] == 0x0A) {
                            logger->info("Found PNG signature at offset " + std::to_string(i));
                            image_data.assign(decrypted_data.begin() + i, decrypted_data.end());
                            found_image = true;
                            break;
                        }
                    }
                }
                
                if (found_image) {
                    // Save to LRIT directory
                    std::string output_dir = directory + "/IMAGES";
                    if (!std::filesystem::exists(output_dir))
                        std::filesystem::create_directories(output_dir);
                    
                    std::string output_file = output_dir + "/decrypted_image";
                    if (image_data[0] == 0xFF && image_data[1] == 0xD8) {
                        output_file += ".jpg";
                    } else if (image_data[0] == 0x89 && image_data[1] == 0x50) {
                        output_file += ".png";
                    } else {
                        output_file += ".bin";
                    }
                    
                    std::ofstream out_file(output_file, std::ios::binary);
                    out_file.write((char*)image_data.data(), image_data.size());
                    out_file.close();
                    
                    logger->info("Saved decrypted image to: " + output_file);
                } else {
                    // Save full decrypted data for debugging
                    std::string output_dir = directory + "/IMAGES/Unknown";
                    if (!std::filesystem::exists(output_dir))
                        std::filesystem::create_directories(output_dir);
                    
                    std::string output_file = output_dir + "/decrypted_data.bin";
                    std::ofstream out_file(output_file, std::ios::binary);
                    out_file.write((char*)decrypted_data.data(), decrypted_data.size());
                    out_file.close();
                    
                    logger->info("No image signature found, saved raw decrypted data to: " + output_file);
                }
                
                return; // DAT file processing complete
            }

            // Original LRIT processing logic
            logger->info("Demultiplexing and deframing...");

            satdump::xrit::XRITDemux lrit_demux(1012, false);

            lrit_demux.onParseHeader = [](satdump::xrit::XRITFile &file) -> void
            {
                if (file.hasHeader<satdump::xrit::fy4::KeyHeader>())
                {
                    satdump::xrit::fy4::KeyHeader key_header = file.getHeader<satdump::xrit::fy4::KeyHeader>();
                    if (key_header.key != 0)
                    {
                        logger->debug("This is encrypted!");
                        file.custom_flags.insert_or_assign(IS_ENCRYPTED, true);
                        file.custom_flags.insert_or_assign(KEY_INDEX, key_header.key);
                    }
                    else
                    {
                        file.custom_flags.insert_or_assign(IS_ENCRYPTED, false);
                    }
                }
                else
                {
                    file.custom_flags.insert_or_assign(IS_ENCRYPTED, false);
                }
            };

            uint8_t cadu[1024];

            while (should_run())
            {
                read_data((uint8_t *)&cadu, 1024);
                std::vector<satdump::xrit::XRITFile> files = lrit_demux.work(cadu);

                for (auto &file : files)
                    processLRITFile(file);
            }

            cleanup();

            for (auto &p : all_processors)
                p.second->flush();
        }

        void FY4LRITDataDecoderModule::drawUI(bool window)
        {
            ImGui::Begin("FY-4x LRIT Data Decoder", NULL, window ? 0 : NOWINDOW_FLAGS);

            // If this is a DAT file, show key input interface
            if (is_dat_file) {
                if (!key_entered) {
                    ImGui::Text("Enter decryption key (16 hex digits):");
                    ImGui::InputText("##key_input", key_input, sizeof(key_input));
                    
                    if (ImGui::Button("Decrypt")) {
                        std::string key_str(key_input);
                        if (parse_key(key_str, key_bytes)) {
                            key_entered = true;
                            logger->info("Key accepted");
                        } else {
                            logger->error("Invalid key format. Please enter 16 hexadecimal characters.");
                        }
                    }
                    
                    ImGui::SameLine();
                    if (ImGui::Button("Cancel")) {
                        // Set stop flag
                        should_stop = true;
                    }
                } else {
                    ImGui::Text("Decrypting...");
                }
            } else {
                all_processors_mtx.lock();
                satdump::xrit::renderAllTabsFromProcessors(all_processors);
                all_processors_mtx.unlock();
                drawProgressBar();
            }

            ImGui::End();
        }

        std::string FY4LRITDataDecoderModule::getID() { return "fy4_lrit_data_decoder"; }

        std::shared_ptr<satdump::pipeline::ProcessingModule> FY4LRITDataDecoderModule::getInstance(std::string input_file, std::string output_file_hint, nlohmann::json parameters)
        {
            return std::make_shared<FY4LRITDataDecoderModule>(input_file, output_file_hint, parameters);
        }
    } // namespace lrit
} // namespace fy4
