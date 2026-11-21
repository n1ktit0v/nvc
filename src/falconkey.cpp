// Copyright (c) 2026 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "falconkey.h"

#include <openssl/sha.h>

void CFalconKey::MakeNewKey()
{
    OQS_SIG *sig = OQS_SIG_falcon_512_new();
    if (sig == NULL)
        throw std::runtime_error("CFalconKey::MakeNewKey() : falcon-512 unavailable");

    vchPubKey.resize(PUBKEY_SIZE);
    vchPrivKey.resize(PRIVKEY_SIZE);

    OQS_STATUS st = OQS_SIG_falcon_512_keypair(&vchPubKey[0], &vchPrivKey[0]);
    OQS_SIG_free(sig);

    if (st != OQS_SUCCESS)
    {
        vchPubKey.clear();
        vchPrivKey.clear();
        fValid = false;
        return;
    }
    fValid = true;
}

bool CFalconKey::SetKeys(const std::vector<unsigned char>& vchPubKeyIn, const std::vector<unsigned char>& vchPrivKeyIn)
{
    if (vchPubKeyIn.size() != PUBKEY_SIZE || vchPrivKeyIn.size() != PRIVKEY_SIZE)
        return false;
    vchPubKey = vchPubKeyIn;
    vchPrivKey = vchPrivKeyIn;
    fValid = true;
    return true;
}

CFalconKeyID CFalconKey::GetID() const
{
    uint256 id;
    SHA256(&vchPubKey[0], vchPubKey.size(), id.begin());
    return CFalconKeyID(id);
}

bool CFalconKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSigOut) const
{
    if (!fValid)
        return false;

    OQS_SIG *sig = OQS_SIG_falcon_512_new();
    if (sig == NULL)
        return false;

    size_t nSigLen = SIGNATURE_SIZE;
    vchSigOut.resize(nSigLen);
    OQS_STATUS st = OQS_SIG_falcon_512_sign(hash.begin(), 32, &vchSigOut[0], &nSigLen);
    OQS_SIG_free(sig);

    if (st != OQS_SUCCESS)
    {
        vchSigOut.clear();
        return false;
    }

    vchSigOut.resize(nSigLen);
    return true;
}

bool CFalconKey::Verify(const uint256& hash, const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchPubKey)
{
    if (vchPubKey.size() != PUBKEY_SIZE)
        return false;

    OQS_SIG *sig = OQS_SIG_falcon_512_new();
    if (sig == NULL)
        return false;

    OQS_STATUS st = OQS_SIG_falcon_512_verify(hash.begin(), 32, vchSig.empty() ? NULL : &vchSig[0], vchSig.size(), &vchPubKey[0]);
    OQS_SIG_free(sig);

    return (st == OQS_SUCCESS);
}

void CFalconKey::SplitForScript(const std::vector<unsigned char>& vch, std::vector<unsigned char>& vch1, std::vector<unsigned char>& vch2)
{
    size_t nHalf = vch.size() / 2;
    vch1.assign(vch.begin(), vch.begin() + nHalf);
    vch2.assign(vch.begin() + nHalf, vch.end());
}
