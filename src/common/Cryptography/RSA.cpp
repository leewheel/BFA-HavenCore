/*
 * 2026 BFA-HavenCore
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "RSA.h"
#include "HMAC.h"
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

namespace
{
struct BIODeleter
{
    void operator()(BIO* bio)
    {
        BIO_free(bio);
    }
};

// By leewheel 2026-08-15
// 用于 Sign 中 RAII 管理每次调用独立创建的 EVP_MD_CTX，保证异常/提前返回路径都不会泄漏。
struct EVP_MD_CTXDeleter
{
    void operator()(EVP_MD_CTX* ctx)
    {
        EVP_MD_CTX_free(ctx);
    }
};
// End By leewheel

// The client expects the EnterEncryptedMode signature to be a PKCS1 signature carrying the sha256 algorithm id,
// but computed over an HMAC-SHA256 of the message - wrap our HMAC in a custom EVP_MD to feed it to EVP_DigestSign
struct HMAC_SHA256_MD
{
    struct CTX_DATA
    {
        Trinity::Crypto::HMAC_SHA256* hmac;
    };

// EVP_MD_meth_* is deprecated in OpenSSL 3.0 with no replacement able to wrap an arbitrary digest implementation
#if TRINITY_COMPILER == TRINITY_COMPILER_GNU
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#else
#pragma warning(push)
#pragma warning(disable: 4996)
#endif

    HMAC_SHA256_MD()
    {
        _md = EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption);
        EVP_MD_meth_set_result_size(_md, Trinity::Crypto::Constants::SHA256_DIGEST_LENGTH_BYTES);
        EVP_MD_meth_set_flags(_md, EVP_MD_FLAG_DIGALGID_ABSENT);
        EVP_MD_meth_set_init(_md, &Init);
        EVP_MD_meth_set_update(_md, &UpdateData);
        EVP_MD_meth_set_final(_md, &Finalize);
        EVP_MD_meth_set_copy(_md, &Copy);
        EVP_MD_meth_set_cleanup(_md, &Cleanup);
        EVP_MD_meth_set_input_blocksize(_md, SHA256_CBLOCK);
        EVP_MD_meth_set_app_datasize(_md, sizeof(EVP_MD*) + sizeof(CTX_DATA*));
    }

    HMAC_SHA256_MD(HMAC_SHA256_MD const&) = delete;
    HMAC_SHA256_MD(HMAC_SHA256_MD&&) = delete;

    HMAC_SHA256_MD& operator=(HMAC_SHA256_MD const&) = delete;
    HMAC_SHA256_MD& operator=(HMAC_SHA256_MD&&) = delete;

    ~HMAC_SHA256_MD()
    {
        EVP_MD_meth_free(_md);
        _md = nullptr;
    }

#if TRINITY_COMPILER == TRINITY_COMPILER_GNU
#pragma GCC diagnostic pop
#else
#pragma warning(pop)
#endif

    operator EVP_MD const* () const
    {
        return _md;
    }

    static int Init(EVP_MD_CTX* ctx)
    {
        Cleanup(ctx);
        return 1;
    }

    static int UpdateData(EVP_MD_CTX* ctx, const void* data, size_t count)
    {
        // By leewheel 2026-08-15
        // 防御性检查：md_data 为 NULL（EVP_DigestSignInit 失败/上下文未就绪）时直接返回失败，
        // 避免空指针解引用崩溃（原崩溃点即此类空指针访问）。
        // End By leewheel
        CTX_DATA* ctxData = reinterpret_cast<CTX_DATA*>(EVP_MD_CTX_md_data(ctx));
        if (!ctxData || !ctxData->hmac)
            return 0;

        ctxData->hmac->UpdateData(reinterpret_cast<uint8 const*>(data), count);
        return 1;
    }

    static int Finalize(EVP_MD_CTX* ctx, unsigned char* md)
    {
        // By leewheel 2026-08-15
        // 同上：md_data 为空时返回失败，防止空指针解引用。
        // End By leewheel
        CTX_DATA* ctxData = reinterpret_cast<CTX_DATA*>(EVP_MD_CTX_md_data(ctx));
        if (!ctxData || !ctxData->hmac)
            return 0;

        ctxData->hmac->Finalize();
        memcpy(md, ctxData->hmac->GetDigest().data(), ctxData->hmac->GetDigest().size());
        return 1;
    }

    // post-processing after openssl memcpys from source to dest (no need to cleanup dest)
    static int Copy(EVP_MD_CTX* to, EVP_MD_CTX const* from)
    {
        // By leewheel 2026-08-15
        // 防御性检查：源/目标 md_data 为空时按无操作成功处理，避免空指针解引用。
        // End By leewheel
        CTX_DATA const* ctxDataFrom = reinterpret_cast<CTX_DATA const*>(EVP_MD_CTX_md_data(from));
        CTX_DATA* ctxDataTo = reinterpret_cast<CTX_DATA*>(EVP_MD_CTX_md_data(to));

        if (!ctxDataFrom || !ctxDataTo)
            return 1;

        if (ctxDataFrom->hmac)
            ctxDataTo->hmac = new Trinity::Crypto::HMAC_SHA256(*ctxDataFrom->hmac);

        return 1;
    }

    static int Cleanup(EVP_MD_CTX* ctx)
    {
        // By leewheel 2026-08-15
        // 防御性检查：md_data 为空时无操作，避免空指针解引用。
        // End By leewheel
        CTX_DATA* data = reinterpret_cast<CTX_DATA*>(EVP_MD_CTX_md_data(ctx));
        if (!data)
            return 1;

        if (data->hmac)
        {
            delete data->hmac;
            data->hmac = nullptr;
        }

        return 1;
    }

private:
    EVP_MD* _md;
} HmacSha256Md;
}

namespace Trinity
{
namespace Crypto
{
EVP_MD const* RsaSignature::SHA256::GetGenerator() const
{
    return EVP_sha256();
}

void RsaSignature::SHA256::PostInitCustomizeContext(EVP_MD_CTX*)
{
}

EVP_MD const* RsaSignature::HMAC_SHA256::GetGenerator() const
{
    return HmacSha256Md;
}

void RsaSignature::HMAC_SHA256::PostInitCustomizeContext(EVP_MD_CTX* ctx)
{
    // By leewheel 2026-08-15
    // 防御性检查：md_data 为 NULL 时无法注入 HMAC 密钥，直接返回；
    // 后续 EVP_DigestSignUpdate/Final 会因 hmac 为空而失败，Sign 已检查返回值。
    // End By leewheel
    HMAC_SHA256_MD::CTX_DATA* ctxData = reinterpret_cast<HMAC_SHA256_MD::CTX_DATA*>(EVP_MD_CTX_md_data(ctx));
    if (!ctxData)
        return;

    if (ctxData->hmac)
        delete ctxData->hmac;

    ctxData->hmac = new Crypto::HMAC_SHA256(_key, _keyLength);
}

RsaSignature::RsaSignature()
{
    // By leewheel 2026-08-15
    // _ctx 成员已移除：Sign 改为每次调用创建独立 EVP_MD_CTX（见 Sign 内注释），
    // 修复多线程并发调用 Sign 复用同一 _ctx 导致的空指针崩溃。
    // End By leewheel
}

RsaSignature::RsaSignature(RsaSignature&& rsa) noexcept
{
    _key = std::exchange(rsa._key, nullptr);
}

RsaSignature::~RsaSignature()
{
    EVP_PKEY_free(_key);
    _key = nullptr;
}

bool RsaSignature::LoadKeyFromFile(std::string const& fileName)
{
    std::unique_ptr<BIO, BIODeleter> keyBIO(BIO_new_file(fileName.c_str(), "r"));
    if (!keyBIO)
        return false;

    // By leewheel 2026-08-15
    // 同类成员复用缺陷修复：重复调用 LoadKey 时先释放旧 _key，避免泄漏。
    // End By leewheel
    EVP_PKEY_free(_key);
    _key = nullptr;

    _key = EVP_PKEY_new();
    if (!PEM_read_bio_PrivateKey(keyBIO.get(), &_key, nullptr, nullptr))
        return false;

    return true;
}

bool RsaSignature::LoadKeyFromString(std::string const& keyPem)
{
    std::unique_ptr<BIO, BIODeleter> keyBIO(BIO_new_mem_buf(
        const_cast<char*>(keyPem.c_str()) /*api hack - this function assumes memory is readonly but lacks const modifier*/,
        keyPem.length() + 1));
    if (!keyBIO)
        return false;

    // By leewheel 2026-08-15
    // 同类成员复用缺陷修复：重复调用 LoadKey 时先释放旧 _key，避免泄漏。
    // End By leewheel
    EVP_PKEY_free(_key);
    _key = nullptr;

    _key = EVP_PKEY_new();
    if (!PEM_read_bio_PrivateKey(keyBIO.get(), &_key, nullptr, nullptr))
        return false;

    return true;
}

bool RsaSignature::Sign(uint8 const* message, std::size_t messageLength, DigestGenerator& generator, std::vector<uint8>& output)
{
    // By leewheel 2026-08-15
    // 修复多线程崩溃(ACCESS_VIOLATION @ PostInitCustomizeContext)：
    // 原实现复用成员 _ctx，而全局 ConnectToRSA 会被多个网络线程(EnterEncryptedMode，玩家登录)
    // 与世界线程(ConnectTo，传送/进副本)并发调用 Sign。并发复用同一 EVP_MD_CTX 时，
    // EVP_DigestSignInit 切换 digest 会先释放旧 md_data 再重建（SHA256 与自定义 HMAC_SHA256
    // 的 ctx_size 不同，必然 free→zalloc），另一线程此刻读取 EVP_MD_CTX_md_data 得到空指针，
    // 在 PostInitCustomizeContext 解引用崩溃（崩溃日志寄存器 RAX=0 即 md_data 为 NULL）。
    // 修复：每次调用创建独立 EVP_MD_CTX（RAII 自动释放），天然线程安全；
    // 同时检查 EVP_DigestSignInit 返回值，初始化失败(如 _key 无效)时直接返回 false，
    // 不再继续操作未初始化的上下文。
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTXDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx)
        return false;

    if (EVP_DigestSignInit(ctx.get(), nullptr, generator.GetGenerator(), nullptr, _key) != 1)
        return false;

    generator.PostInitCustomizeContext(ctx.get());

    size_t signatureLength = 0;
    if (EVP_DigestSignUpdate(ctx.get(), message, messageLength) != 1)
        return false;

    if (EVP_DigestSignFinal(ctx.get(), nullptr, &signatureLength) != 1)
        return false;

    output.resize(signatureLength);
    if (EVP_DigestSignFinal(ctx.get(), output.data(), &signatureLength) != 1)
        return false;

    std::reverse(output.begin(), output.end());
    return true;
}
}
}
