#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <unordered_set>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mutex>
#include <stdexcept>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define DOGE_PUBKEY_HASH 0x1E
#define HARDENED_OFFSET 0x80000000

struct HDNode {
    std::vector<uint8_t> privkey;
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> chaincode;
};

static void ensure(bool cond, const char* msg) {
    if (!cond) throw std::runtime_error(msg);
}

std::vector<std::string> load_wordlist(const std::string &filename) {
    std::ifstream file(filename);
    ensure(file.good(), "Nao consegui abrir wordlist.txt.");
    std::vector<std::string> words;
    std::string word;
    while (std::getline(file, word)) {
        if (!word.empty()) words.push_back(word);
    }
    ensure(words.size() == 2048, "wordlist.txt invalida: precisa conter 2048 palavras.");
    return words;
}

std::unordered_set<std::string> load_address_list(const std::string& filename) {
    std::ifstream in(filename);
    ensure(in.good(), "Nao consegui abrir enderecos.txt.");
    std::unordered_set<std::string> s;
    std::string line;
    while (std::getline(in, line)) if (!line.empty()) s.insert(line);
    ensure(!s.empty(), "enderecos.txt esta vazio.");
    return s;
}

std::vector<uint8_t> random_entropy(size_t bits) {
    size_t bytes = bits / 8;
    std::vector<uint8_t> entropy(bytes);
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0,255);
    for (size_t i = 0; i < bytes; i++) entropy[i] = static_cast<uint8_t>(dist(rd));
    return entropy;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t> &data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> ripemd160(const std::vector<uint8_t> &data) {
    std::vector<uint8_t> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(data.data(), data.size(), hash.data());
    return hash;
}

std::string entropy_to_mnemonic(const std::vector<uint8_t> &entropy, const std::vector<std::string> &wordlist) {
    const size_t entBits = entropy.size() * 8;
    const size_t checksumBits = entBits / 32;
    const auto hash = sha256(entropy);

    std::string bits;
    for (uint8_t byte : entropy)
        for (int i = 7; i >= 0; --i)
            bits += ((byte >> i) & 1) ? '1' : '0';

    uint8_t checksumByte = hash[0];
    for (size_t i = 0; i < checksumBits; ++i)
        bits += ((checksumByte >> (7 - i)) & 1) ? '1' : '0';

    std::vector<std::string> mnemonic;
    for (size_t i = 0; i < bits.size(); i += 11) {
        int idx = std::stoi(bits.substr(i, 11), nullptr, 2);
        mnemonic.push_back(wordlist[idx]);
    }

    std::string out;
    for (size_t i = 0; i < mnemonic.size(); ++i) {
        out += mnemonic[i];
        if (i + 1 < mnemonic.size()) out += " ";
    }
    return out;
}

std::vector<uint8_t> mnemonic_to_seed(const std::string &mnemonic, const std::string &passphrase) {
    std::string salt = "mnemonic" + passphrase;
    std::vector<uint8_t> seed(64);
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), (int)mnemonic.size(),
                      reinterpret_cast<const unsigned char*>(salt.c_str()), (int)salt.size(),
                      2048, EVP_sha512(), 64, seed.data());
    return seed;
}

HDNode bip32_master_key(const std::vector<uint8_t> &seed) {
    HDNode node;
    unsigned char out[64];
    unsigned int len = 0;
    HMAC(EVP_sha512(), "Bitcoin seed", 12, seed.data(), seed.size(), out, &len);
    node.privkey.assign(out, out + 32);
    node.chaincode.assign(out + 32, out + 64);
    return node;
}

std::vector<uint8_t> priv_to_pub(const std::vector<uint8_t> &privkey) {
    std::vector<uint8_t> pubkey(33);
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *prv = BN_bin2bn(privkey.data(), privkey.size(), NULL);
    EC_KEY_set_private_key(ec_key, prv);

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, pub_point, prv, NULL, NULL, NULL);

    EC_KEY_set_public_key(ec_key, pub_point);
    EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, pubkey.data(), pubkey.size(), NULL);

    EC_POINT_free(pub_point);
    BN_free(prv);
    EC_KEY_free(ec_key);
    return pubkey;
}

HDNode bip32_ckd(const HDNode &parent, uint32_t index) {
    HDNode child;
    std::vector<uint8_t> data;

    if (index & HARDENED_OFFSET) {
        data.push_back(0x00);
        data.insert(data.end(), parent.privkey.begin(), parent.privkey.end());
    } else {
        std::vector<uint8_t> pub = priv_to_pub(parent.privkey);
        data.insert(data.end(), pub.begin(), pub.end());
    }

    data.push_back((index >> 24) & 0xFF);
    data.push_back((index >> 16) & 0xFF);
    data.push_back((index >> 8) & 0xFF);
    data.push_back(index & 0xFF);

    unsigned char out[64];
    unsigned int len = 0;
    HMAC(EVP_sha512(), parent.chaincode.data(), parent.chaincode.size(),
         data.data(), data.size(), out, &len);

    BIGNUM *kpar = BN_bin2bn(parent.privkey.data(), parent.privkey.size(), NULL);
    BIGNUM *il = BN_bin2bn(out, 32, NULL);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_GROUP_get_order(group, order, ctx);

    BN_mod_add(il, il, kpar, order, ctx);
    child.privkey.resize(32);
    BN_bn2binpad(il, child.privkey.data(), 32);

    child.chaincode.assign(out + 32, out + 64);

    BN_free(kpar);
    BN_free(il);
    BN_free(order);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return child;
}

std::string pubkey_to_doge_address(const std::vector<uint8_t> &pubkey) {
    auto sha = sha256(pubkey);
    auto ripe = ripemd160(sha);

    std::vector<uint8_t> payload;
    payload.push_back(DOGE_PUBKEY_HASH);
    payload.insert(payload.end(), ripe.begin(), ripe.end());

    auto chk = sha256(sha256(payload));
    payload.insert(payload.end(), chk.begin(), chk.begin() + 4);

    const char *alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string result;

    std::vector<uint8_t> temp = payload;
    int zeroes = 0;
    while (zeroes < (int)temp.size() && temp[zeroes] == 0) zeroes++;

    std::vector<uint8_t> b58;
    int start = zeroes;
    while (start < (int)temp.size()) {
        int carry = 0;
        for (int i = start; i < (int)temp.size(); i++) {
            int val = (int)temp[i] + (carry << 8);
            temp[i] = (uint8_t)(val / 58);
            carry = val % 58;
        }
        b58.push_back((uint8_t)carry);
        while (start < (int)temp.size() && temp[start] == 0) start++;
    }
    for (int i = 0; i < zeroes; i++) result += '1';
    for (auto it = b58.rbegin(); it != b58.rend(); ++it) result += alphabet[*it];

    return result;
}

void worker(size_t bits, const std::vector<std::string> &wordlist, const std::unordered_set<std::string> &lista,
            std::atomic<bool> &found, std::mutex &out_mutex, std::atomic<uint64_t> &contador) {
    while (!found.load()) {
        auto entropy = random_entropy(bits);
        std::string mnemonic = entropy_to_mnemonic(entropy, wordlist);
        auto seed = mnemonic_to_seed(mnemonic, "");
        auto master = bip32_master_key(seed);

        auto m44h = bip32_ckd(master, 44 | HARDENED_OFFSET);
        auto m44h_3h = bip32_ckd(m44h, 3 | HARDENED_OFFSET);
        auto m44h_3h_0h = bip32_ckd(m44h_3h, 0 | HARDENED_OFFSET);
        auto m44h_3h_0h_0 = bip32_ckd(m44h_3h_0h, 0);
        auto child = bip32_ckd(m44h_3h_0h_0, 0);

        child.pubkey = priv_to_pub(child.privkey);
        std::string address = pubkey_to_doge_address(child.pubkey);

        uint64_t num = ++contador;
        {
            std::lock_guard<std::mutex> lock(out_mutex);
            std::cout << "[" << std::setw(13) << std::setfill('0') << num << "] " << address << "\n";
        }

        if (lista.find(address) != lista.end()) {
            std::lock_guard<std::mutex> lock(out_mutex);
            std::cout << "\n=== ENCONTRADO ===\nMnemonic: " << mnemonic << "\nEndereco: " << address << "\n";
            found.store(true);
        }
    }
}

int main() {
    int opcao, num_threads;
    std::cout << "Selecione (1) 12 palavras, (2) 18 palavras, (3) 24 palavras: ";
    std::cin >> opcao;
    std::cout << "Numero de threads (0 = usar todos nucleos): ";
    std::cin >> num_threads;

    if (num_threads <= 0) num_threads = std::thread::hardware_concurrency();

    size_t bits = (opcao == 1 ? 128 : (opcao == 2 ? 192 : 256));
    auto wordlist = load_wordlist("wordlist.txt");
    auto lista = load_address_list("enderecos.txt");

    std::atomic<bool> found(false);
    std::atomic<uint64_t> contador(0);
    std::mutex out_mutex;
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(worker, bits, std::cref(wordlist), std::cref(lista),
                             std::ref(found), std::ref(out_mutex), std::ref(contador));
    }

    for (auto &t : threads) t.join();

    return 0;
}
