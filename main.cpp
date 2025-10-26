#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <string>
#include <string_view>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cerrno>

#include <fcntl.h>
#include <unistd.h>

#if defined(__has_include)
#  if __has_include(<sys/random.h>)
#    include <sys/random.h>
#    define HAVE_GETRANDOM 1
#  endif
#endif
#ifndef HAVE_GETRANDOM
#  define HAVE_GETRANDOM 0
#endif

#if defined(__GNUC__) && !defined(_WIN32)
#  define EXPORT __attribute__((visibility("default")))
#else
#  define EXPORT
#endif

static void fill_random_bytes(uint8_t* buf, size_t len) {
    if (!buf && len) throw std::invalid_argument("fill_random_bytes: null buffer");
    if (len == 0) return;

#if HAVE_GETRANDOM
    {
        size_t off = 0;
        while (off < len) {
            ssize_t r = getrandom(buf + off, len - off, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                if (errno == ENOSYS) break;
                throw std::runtime_error("getrandom failed (errno=" + std::to_string(errno) + ")");
            }
            off += static_cast<size_t>(r);
        }
        if (off == len) return;
    }
#endif

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("open(/dev/urandom) failed (errno=" + std::to_string(errno) + ")");

    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            close(fd);
            throw std::runtime_error("read(/dev/urandom) failed (errno=" + std::to_string(e) + ")");
        }
        if (r == 0) { close(fd); throw std::runtime_error("EOF on /dev/urandom"); }
        off += static_cast<size_t>(r);
    }
    close(fd);
}

static std::string GenerateCryptoString(
    size_t length,
    std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
) {
    const size_t m = alphabet.size();
    if (m < 2 || m > 256) throw std::invalid_argument("alphabet size must be in [2..256]");
    const uint32_t threshold = (256u / static_cast<uint32_t>(m)) * static_cast<uint32_t>(m);

    std::string out;
    out.reserve(length);

    std::vector<uint8_t> buf(128);
    while (out.size() < length) {
        fill_random_bytes(buf.data(), buf.size());
        for (uint8_t r : buf) {
            if (r >= threshold) continue;
            out.push_back(alphabet[r % m]);
            if (out.size() == length) break;
        }
    }
    return out;
}

static inline uint64_t RotateRight64(uint64_t value, unsigned int count) {
    uint64_t right_part = value >> count;
    uint64_t left_part = value << (64 - count);
    return right_part | left_part;
}

static inline uint64_t LoadLittleEndian64(const uint8_t* address) {
    uint64_t result = 0;
    result |= static_cast<uint64_t>(address[0]) << 0;
    result |= static_cast<uint64_t>(address[1]) << 8;
    result |= static_cast<uint64_t>(address[2]) << 16;
    result |= static_cast<uint64_t>(address[3]) << 24;
    result |= static_cast<uint64_t>(address[4]) << 32;
    result |= static_cast<uint64_t>(address[5]) << 40;
    result |= static_cast<uint64_t>(address[6]) << 48;
    result |= static_cast<uint64_t>(address[7]) << 56;
    return result;
}

static inline void StoreLittleEndian64(uint8_t* address, uint64_t value) {
    address[0] = static_cast<uint8_t>(value & 0xFF);
    address[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    address[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    address[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    address[4] = static_cast<uint8_t>((value >> 32) & 0xFF);
    address[5] = static_cast<uint8_t>((value >> 40) & 0xFF);
    address[6] = static_cast<uint8_t>((value >> 48) & 0xFF);
    address[7] = static_cast<uint8_t>((value >> 56) & 0xFF);
}

static const uint64_t INITIAL_VECTOR[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const uint8_t SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

struct Blake2bState {
    uint64_t chaining_value[8];
    uint64_t byte_counter[2];
    uint64_t finalization_flag[2];
    uint8_t  buffer[128];
    size_t   buffered_bytes;
    size_t   requested_output_length;
};

static void MixingFunctionG(
    uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d,
    uint64_t x, uint64_t y
) {
    a = a + b + x; d ^= a; d = RotateRight64(d, 32);
    c = c + d;     b ^= c; b = RotateRight64(b, 24);
    a = a + b + y; d ^= a; d = RotateRight64(d, 16);
    c = c + d;     b ^= c; b = RotateRight64(b, 63);
}

static void CompressOneBlock(Blake2bState& s, const uint8_t block[128]) {
    uint64_t m[16];
    for (size_t i = 0; i < 16; ++i) m[i] = LoadLittleEndian64(block + i * 8);

    uint64_t v[16];
    for (size_t i = 0; i < 8; ++i) v[i] = s.chaining_value[i];
    for (size_t i = 0; i < 8; ++i) v[8 + i] = INITIAL_VECTOR[i];

    v[12] ^= s.byte_counter[0];
    v[13] ^= s.byte_counter[1];
    v[14] ^= s.finalization_flag[0];
    v[15] ^= s.finalization_flag[1];

    for (size_t r = 0; r < 12; ++r) {
        const uint8_t* p = SIGMA[r];
        MixingFunctionG(v[0], v[4], v[8], v[12], m[p[0]], m[p[1]]);
        MixingFunctionG(v[1], v[5], v[9], v[13], m[p[2]], m[p[3]]);
        MixingFunctionG(v[2], v[6], v[10], v[14], m[p[4]], m[p[5]]);
        MixingFunctionG(v[3], v[7], v[11], v[15], m[p[6]], m[p[7]]);
        MixingFunctionG(v[0], v[5], v[10], v[15], m[p[8]], m[p[9]]);
        MixingFunctionG(v[1], v[6], v[11], v[12], m[p[10]], m[p[11]]);
        MixingFunctionG(v[2], v[7], v[8], v[13], m[p[12]], m[p[13]]);
        MixingFunctionG(v[3], v[4], v[9], v[14], m[p[14]], m[p[15]]);
    }

    for (size_t i = 0; i < 8; ++i) s.chaining_value[i] ^= v[i] ^ v[8 + i];
}

static void InitializeState(Blake2bState& s, size_t out_len) {
    std::memset(&s, 0, sizeof(s));
    s.requested_output_length = (out_len > 64) ? 64 : out_len;

    for (size_t i = 0; i < 8; ++i) s.chaining_value[i] = INITIAL_VECTOR[i];
    const uint64_t param_block = 0x01010000ULL ^ static_cast<uint64_t>(s.requested_output_length);
    s.chaining_value[0] ^= param_block;

    s.byte_counter[0] = 0;
    s.byte_counter[1] = 0;
    s.finalization_flag[0] = 0;
    s.finalization_flag[1] = 0;
    s.buffered_bytes = 0;
}

static void UpdateState(Blake2bState& s, const uint8_t* in, size_t in_len) {
    if (in_len == 0) return;

    size_t have = s.buffered_bytes;
    size_t need = 128 - have;

    if (have > 0 && in_len >= need) {
        std::memcpy(s.buffer + have, in, need);
        s.byte_counter[0] += 128;
        if (s.byte_counter[0] < 128) s.byte_counter[1] += 1;
        CompressOneBlock(s, s.buffer);
        s.buffered_bytes = 0;
        in += need;
        in_len -= need;
    }

    while (in_len >= 128) {
        s.byte_counter[0] += 128;
        if (s.byte_counter[0] < 128) s.byte_counter[1] += 1;
        CompressOneBlock(s, in);
        in += 128;
        in_len -= 128;
    }

    if (in_len > 0) {
        std::memcpy(s.buffer + s.buffered_bytes, in, in_len);
        s.buffered_bytes += in_len;
    }
}

static void FinalizeHash(Blake2bState& s, uint8_t* out) {
    s.finalization_flag[0] = ~0ULL;

    s.byte_counter[0] += s.buffered_bytes;
    if (s.byte_counter[0] < s.buffered_bytes) s.byte_counter[1] += 1;

    uint8_t last_block[128];
    std::memset(last_block, 0, sizeof(last_block));
    if (s.buffered_bytes > 0) std::memcpy(last_block, s.buffer, s.buffered_bytes);
    CompressOneBlock(s, last_block);

    uint8_t full_hash[64];
    for (size_t i = 0; i < 8; ++i) StoreLittleEndian64(full_hash + i * 8, s.chaining_value[i]);
    std::memcpy(out, full_hash, s.requested_output_length);
    std::memset(full_hash, 0, sizeof(full_hash));
}

static std::vector<uint8_t> Blake2bHash(const uint8_t* input, size_t input_length, size_t out_len_bytes = 64) {
    Blake2bState s;
    InitializeState(s, out_len_bytes);
    UpdateState(s, input, input_length);

    std::vector<uint8_t> out(out_len_bytes <= 64 ? out_len_bytes : 64);
    FinalizeHash(s, out.data());
    return out;
}

static std::string ToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

EXPORT std::vector<std::string>
GenerateKeyHexes(size_t count, size_t seed_len =24, size_t out_len_bytes =64) {
    if (count == 0) return {};
    if (out_len_bytes == 0 || out_len_bytes > 64) {
        throw std::invalid_argument("out_len_bytes must be in [1..64]");
    }

    std::vector<std::string> keys;
    keys.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        std::string seed = GenerateCryptoString(seed_len);
        std::vector<uint8_t> hash = Blake2bHash(
            reinterpret_cast<const uint8_t*>(seed.data()),
            seed.size(),
            out_len_bytes
        );
        keys.push_back(ToHex(hash));
    }
    return keys;
}

int main(int argc, char** argv) {
    size_t count    = static_cast<size_t>(std::stoull(argv[1]));
    size_t seed_len = (argc > 2) ? static_cast<size_t>(std::stoull(argv[2])) : 24;
    size_t out_len  = (argc > 3) ? static_cast<size_t>(std::stoull(argv[3])) : 64;

    auto keys = GenerateKeyHexes(count, seed_len, out_len);
    for (const auto& k : keys) {
        std::cout << k << '\n';
    }
    return 0;
}
