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
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
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

struct EVP_PKEY_CTXDeleter
{
    void operator()(EVP_PKEY_CTX* ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
};

extern OSSL_DISPATCH const HMAC_SHA256_funcs[];
extern OSSL_ALGORITHM const HMAC_SHA256_algs[];
extern OSSL_DISPATCH const HMAC_SHA256_method[];

// The client expects the EnterEncryptedMode signature to be a PKCS1 signature carrying the sha256 algorithm id,
// but computed over an HMAC-SHA256 of the message - expose the HMAC to EVP_DigestSign as a provider supplied digest
struct HMAC_SHA256_MD
{
    struct CTX_DATA
    {
        Trinity::Crypto::HMAC_SHA256* hmac;
    };

    HMAC_SHA256_MD()
    {
        _lib = OSSL_LIB_CTX_new();
        OSSL_PROVIDER_add_builtin(_lib, "havencore-rsa-hmac-sha256", &InitProvider);
        // retain fallbacks so RSA itself still resolves from the default provider inside this library context
        _handle = OSSL_PROVIDER_try_load(_lib, "havencore-rsa-hmac-sha256", 1);
    }

    HMAC_SHA256_MD(HMAC_SHA256_MD const&) = delete;
    HMAC_SHA256_MD(HMAC_SHA256_MD&&) = delete;

    HMAC_SHA256_MD& operator=(HMAC_SHA256_MD const&) = delete;
    HMAC_SHA256_MD& operator=(HMAC_SHA256_MD&&) = delete;

    ~HMAC_SHA256_MD()
    {
        if (_handle)
            OSSL_PROVIDER_unload(_handle);
        if (_lib)
            OSSL_LIB_CTX_free(_lib);
    }

    OSSL_LIB_CTX* GetLib() const
    {
        return _lib;
    }

    static int InitProvider(OSSL_CORE_HANDLE const* /*handle*/, OSSL_DISPATCH const* /*in*/, OSSL_DISPATCH const** out, void** /*provctx*/)
    {
        *out = HMAC_SHA256_method;
        return 1;
    }

    static OSSL_ALGORITHM const* QueryProvider(void* /*provctx*/, int operation_id, int* no_cache)
    {
        *no_cache = 0;
        if (operation_id == OSSL_OP_DIGEST)
            return HMAC_SHA256_algs;

        return nullptr;
    }

    static CTX_DATA* DigestNew()
    {
        CTX_DATA* data = new CTX_DATA();
        data->hmac = nullptr;
        return data;
    }

    static int DigestInit(void* dctx, OSSL_PARAM const* params)
    {
        CTX_DATA* ctxData = reinterpret_cast<CTX_DATA*>(dctx);

        delete ctxData->hmac;
        ctxData->hmac = nullptr;
        if (OSSL_PARAM const* keyParam = OSSL_PARAM_locate_const(params, "hmac-key"))
        {
            uint8 const* key = nullptr;
            size_t keyLength = 0;
            if (OSSL_PARAM_get_octet_ptr(keyParam, reinterpret_cast<void const**>(&key), &keyLength))
            {
                ctxData->hmac = new Trinity::Crypto::HMAC_SHA256(key, keyLength);
                return 1;
            }
        }

        return 0;
    }

    static int DigestUpdate(void* dctx, unsigned char const* in, size_t inl)
    {
        // By leewheel 2026-08-16
        // 防御性检查（review 收尾）：DigestInit 失败/未携带 hmac-key 参数时 hmac 为空，
        // 直接返回失败避免空指针解引用（与本地 legacy 版修复保持一致）。
        // End By leewheel
        CTX_DATA* ctxData = reinterpret_cast<CTX_DATA*>(dctx);
        if (!ctxData || !ctxData->hmac)
            return 0;

        ctxData->hmac->UpdateData(in, inl);
        return 1;
    }

    static int DigestFinal(void* dctx, unsigned char* out, size_t* outl, size_t outsz)
    {
        // By leewheel 2026-08-16
        // 防御性检查：同上，hmac 为空时返回失败，防止空指针解引用。
        // End By leewheel
        CTX_DATA* ctxData = reinterpret_cast<CTX_DATA*>(dctx);
        if (!ctxData || !ctxData->hmac)
            return 0;

        ctxData->hmac->Finalize();
        *outl = std::min(ctxData->hmac->GetDigest().size(), outsz);
        memcpy(out, ctxData->hmac->GetDigest().data(), *outl);
        return 1;
    }

    static void DigestFree(void* dctx)
    {
        CTX_DATA* data = reinterpret_cast<CTX_DATA*>(dctx);
        delete data->hmac;
        data->hmac = nullptr;
        delete data;
    }

    static void* DigestDup(void* dctx)
    {
        CTX_DATA const* ctxDataFrom = reinterpret_cast<CTX_DATA const*>(dctx);
        CTX_DATA* ctxDataTo = DigestNew();
        if (ctxDataFrom->hmac)
            ctxDataTo->hmac = new Trinity::Crypto::HMAC_SHA256(*ctxDataFrom->hmac);

        return ctxDataTo;
    }

    static int DigestGetParams(OSSL_PARAM params[])
    {
        OSSL_PARAM* p = nullptr;

        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
        if (p != nullptr && !OSSL_PARAM_set_size_t(p, SHA256_CBLOCK))
            return 0;

        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
        if (p != nullptr && !OSSL_PARAM_set_size_t(p, Trinity::Crypto::Constants::SHA256_DIGEST_LENGTH_BYTES))
            return 0;

        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
        if (p != nullptr && !OSSL_PARAM_set_int(p, 0))
            return 0;

        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
        if (p != nullptr && !OSSL_PARAM_set_int(p, 1))
            return 0;

        return 1;
    }

    static OSSL_PARAM const* DigestGettableParams()
    {
        static constexpr OSSL_PARAM Params[] =
        {
            OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, nullptr),
            OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, nullptr),
            OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, nullptr),
            OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, nullptr),
            OSSL_PARAM_END
        };

        return Params;
    }

private:
    OSSL_LIB_CTX* _lib;
    OSSL_PROVIDER* _handle;
} const HmacSha256Md;

OSSL_DISPATCH const HMAC_SHA256_funcs[] =
{
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)())HMAC_SHA256_MD::DigestNew },
    { OSSL_FUNC_DIGEST_INIT, (void (*)())HMAC_SHA256_MD::DigestInit },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)())HMAC_SHA256_MD::DigestUpdate },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)())HMAC_SHA256_MD::DigestFinal },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)())HMAC_SHA256_MD::DigestFree },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)())HMAC_SHA256_MD::DigestDup },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)())HMAC_SHA256_MD::DigestGetParams },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)())HMAC_SHA256_MD::DigestGettableParams },
    { 0, nullptr }
};

OSSL_ALGORITHM const HMAC_SHA256_algs[] =
{
    // pretend this custom HMAC_SHA256 is a regular SHA256 - openssl has a whitelist of allowed digests for RSA and HMAC_SHA256 is not on it
    { OSSL_DIGEST_NAME_SHA2_256, "provider=havencore-rsa-hmac-sha256", HMAC_SHA256_funcs, "HMAC SHA256 \"digest\" for RSA" },
    { nullptr, nullptr, nullptr, nullptr }
};

OSSL_DISPATCH const HMAC_SHA256_method[] =
{
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)())HMAC_SHA256_MD::QueryProvider },
    { 0, nullptr },
};
}

namespace Trinity
{
namespace Crypto
{
void RsaSignature::DigestGenerator::EVP_MD_Deleter::operator()(EVP_MD* md) const
{
    EVP_MD_free(md);
}

std::unique_ptr<EVP_MD, RsaSignature::DigestGenerator::EVP_MD_Deleter> RsaSignature::SHA256::GetGenerator() const
{
    return std::unique_ptr<EVP_MD, EVP_MD_Deleter>(EVP_MD_fetch(nullptr, OSSL_DIGEST_NAME_SHA2_256, "provider=default"));
}

OSSL_LIB_CTX* RsaSignature::SHA256::GetLib() const
{
    return nullptr;
}

std::unique_ptr<OSSL_PARAM[]> RsaSignature::SHA256::GetParams() const
{
    return nullptr;
}

std::unique_ptr<EVP_MD, RsaSignature::DigestGenerator::EVP_MD_Deleter> RsaSignature::HMAC_SHA256::GetGenerator() const
{
    return std::unique_ptr<EVP_MD, EVP_MD_Deleter>(EVP_MD_fetch(HmacSha256Md.GetLib(), OSSL_DIGEST_NAME_SHA2_256, "provider=havencore-rsa-hmac-sha256"));
}

OSSL_LIB_CTX* RsaSignature::HMAC_SHA256::GetLib() const
{
    return HmacSha256Md.GetLib();
}

std::unique_ptr<OSSL_PARAM[]> RsaSignature::HMAC_SHA256::GetParams() const
{
    return std::unique_ptr<OSSL_PARAM[]>(new OSSL_PARAM[2]
    {
        OSSL_PARAM_octet_ptr("hmac-key", const_cast<void**>(reinterpret_cast<void const* const*>(&_key)), _keyLength),
        OSSL_PARAM_END
    });
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
    {
        // By leewheel 2026-08-16
        // review 收尾：失败时释放残留的空 _key（EVP_PKEY_new 分配），避免残留无效对象。
        // End By leewheel
        EVP_PKEY_free(_key);
        _key = nullptr;
        return false;
    }

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
    {
        // By leewheel 2026-08-16
        // review 收尾：失败时释放残留的空 _key（EVP_PKEY_new 分配），避免残留无效对象。
        // End By leewheel
        EVP_PKEY_free(_key);
        _key = nullptr;
        return false;
    }

    return true;
}

bool RsaSignature::Sign(uint8 const* message, std::size_t messageLength, DigestGenerator& generator, std::vector<uint8>& output)
{
    // By leewheel 2026-08-15
    // 合并上游 #281（provider 方案，根治 OpenSSL 3.x 下 legacy EVP_MD 回调不被调用的问题）
    // 后叠加本地的多线程安全修复：上游实现仍复用成员 _ctx，而全局 ConnectToRSA 会被
    // 多个网络线程(EnterEncryptedMode，玩家登录)与世界线程(ConnectTo，传送/进副本)并发调用
    // Sign，并发复用同一 EVP_MD_CTX 会产生数据竞争（EVP_DigestSignInit_ex 反复重建内部状态）。
    // 修复：每次调用创建独立 EVP_MD_CTX（RAII 自动释放），天然线程安全；
    // 同时 keyCtx 通过 EVP_MD_CTX_set_pkey_ctx 转移所有权给 EVP_MD_CTX（release() 后由
    // EVP_MD_CTX_free 统一释放），避免双重释放。
    std::unique_ptr<EVP_MD, DigestGenerator::EVP_MD_Deleter> digestGenerator = generator.GetGenerator();
    if (!digestGenerator)
        return false;

    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTXDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx)
        return false;

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter> keyCtx(EVP_PKEY_CTX_new_from_pkey(generator.GetLib(), _key, nullptr));
    if (!keyCtx)
        return false;

    // By leewheel 2026-08-16
    // 说明：EVP_MD_CTX_set_pkey_ctx 返回 void（OpenSSL 3.x），无法检查返回值；
    // 其内部无失败路径（仅 free 旧 pctx 后赋值）。所有权转移后由 EVP_MD_CTX_free
    // 统一释放，release() 防止双重释放。
    // End By leewheel
    EVP_MD_CTX_set_pkey_ctx(ctx.get(), keyCtx.get());
    // 所有权已转移给 EVP_MD_CTX，由 EVP_MD_CTX_free 释放，防止双重释放
    keyCtx.release();

    std::unique_ptr<OSSL_PARAM[]> params = generator.GetParams();
    if (EVP_DigestSignInit_ex(ctx.get(), nullptr, EVP_MD_get0_name(digestGenerator.get()), generator.GetLib(), nullptr, _key, params.get()) == 0)
        return false;

    if (EVP_DigestSignUpdate(ctx.get(), message, messageLength) == 0)
        return false;

    size_t signatureLength = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &signatureLength) == 0)
        return false;

    output.resize(signatureLength);
    if (EVP_DigestSignFinal(ctx.get(), output.data(), &signatureLength) == 0)
        return false;

    std::reverse(output.begin(), output.end());
    return true;
}
}
}
