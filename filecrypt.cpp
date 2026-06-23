// filecrypt.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

const string RESET = "\033[0m";
const string GREEN = "\033[92m";
const string RED = "\033[91m";
const string YELLOW = "\033[93m";

string colorize(const string& text, const string& color) {
    return color + text + RESET;
}

const int SALT_LEN = 16;
const int NONCE_LEN = 12;
const int TAG_LEN = 16;
const int KEY_LEN = 32;
const int ITERATIONS = 100000;
const size_t CHUNK_SIZE = 64 * 1024;

vector<unsigned char> deriveKey(const string& password, const vector<unsigned char>& salt) {
    vector<unsigned char> key(KEY_LEN);
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                      salt.data(), salt.size(),
                      ITERATIONS, EVP_sha256(), KEY_LEN, key.data());
    return key;
}

void encryptFile(const string& inputPath, const string& outputPath, const string& password) {
    vector<unsigned char> salt(SALT_LEN), nonce(NONCE_LEN);
    if (!RAND_bytes(salt.data(), SALT_LEN)) throw runtime_error("RAND_bytes failed");
    if (!RAND_bytes(nonce.data(), NONCE_LEN)) throw runtime_error("RAND_bytes failed");

    vector<unsigned char> key = deriveKey(password, salt);

    ifstream in(inputPath, ios::binary);
    if (!in) throw runtime_error("Cannot open input file");
    string plaintext((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data());

    int len;
    vector<unsigned char> ciphertext(plaintext.size() + 16);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    ofstream out(outputPath, ios::binary);
    out.write((char*)salt.data(), SALT_LEN);
    out.write((char*)nonce.data(), NONCE_LEN);
    out.write((char*)ciphertext.data(), ciphertext_len);
    out.write((char*)tag, TAG_LEN);
    out.close();

    cout << colorize("File encrypted successfully: " + outputPath, GREEN) << endl;
}

void decryptFile(const string& inputPath, const string& outputPath, const string& password) {
    ifstream in(inputPath, ios::binary);
    if (!in) throw runtime_error("Cannot open input file");
    vector<unsigned char> salt(SALT_LEN), nonce(NONCE_LEN);
    in.read((char*)salt.data(), SALT_LEN);
    in.read((char*)nonce.data(), NONCE_LEN);
    if (!in) throw runtime_error("Invalid file format");

    // Read rest of file
    string rest((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();
    if (rest.size() < TAG_LEN) throw runtime_error("File too short");
    vector<unsigned char> ciphertext(rest.begin(), rest.end() - TAG_LEN);
    unsigned char tag[TAG_LEN];
    memcpy(tag, rest.data() + rest.size() - TAG_LEN, TAG_LEN);

    vector<unsigned char> key = deriveKey(password, salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    vector<unsigned char> plaintext(ciphertext.size());
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) throw runtime_error("Decryption failed (wrong password or corrupted file)");
    plaintext_len += len;

    ofstream out(outputPath, ios::binary);
    out.write((char*)plaintext.data(), plaintext_len);
    out.close();

    cout << colorize("File decrypted successfully: " + outputPath, GREEN) << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        cerr << colorize("Usage: filecrypt encrypt|decrypt <input> <output> <password>", YELLOW) << endl;
        return 1;
    }
    string mode = argv[1];
    string input = argv[2];
    string output = argv[3];
    string password = argv[4];

    try {
        if (mode == "encrypt") encryptFile(input, output, password);
        else if (mode == "decrypt") decryptFile(input, output, password);
        else {
            cerr << colorize("Invalid mode. Use encrypt or decrypt.", RED) << endl;
            return 1;
        }
    } catch (const exception& e) {
        cerr << colorize("Error: " + string(e.what()), RED) << endl;
        return 1;
    }
    return 0;
}
