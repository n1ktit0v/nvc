// Copyright (c) 2026 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NOVACOIN_FALCONKEY_H
#define NOVACOIN_FALCONKEY_H

#include <stdexcept>
#include <vector>

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"

#include <oqs/oqs.h>

/** A reference to a CFalconKey: the SHA256 of its serialized public key */
class CFalconKeyID : public uint256
{
public:
    CFalconKeyID() {}
    CFalconKeyID(const uint256& in) : uint256(in) {}
};

/** A Falcon-512 (post-quantum) key pair.
 *
 * Public key:  OQS_SIG_falcon_512_length_public_key bytes
 * Secret key:  OQS_SIG_falcon_512_length_secret_key bytes
 * Signatures:  up to OQS_SIG_falcon_512_length_signature bytes (variable length)
 */
class CFalconKey
{
private:
    std::vector<unsigned char> vchPubKey;
    std::vector<unsigned char> vchPrivKey;
    bool fValid;

public:
    static const size_t PUBKEY_SIZE = OQS_SIG_falcon_512_length_public_key;
    static const size_t PRIVKEY_SIZE = OQS_SIG_falcon_512_length_secret_key;
    static const size_t SIGNATURE_SIZE = OQS_SIG_falcon_512_length_signature;
    static const size_t HASH_SIZE = 32;

    CFalconKey() : fValid(false) {}

    void MakeNewKey();

    bool IsValid() const { return fValid; }

    const std::vector<unsigned char>& GetPubKey() const { return vchPubKey; }
    const std::vector<unsigned char>& GetPrivKey() const { return vchPrivKey; }

    bool SetKeys(const std::vector<unsigned char>& vchPubKeyIn, const std::vector<unsigned char>& vchPrivKeyIn);

    //! SHA256(pubkey) - same commitment that OP_FALCONVERIFY checks against
    CFalconKeyID GetID() const;

    //! Sign a 32-byte message (sighash). Returns raw variable-length falcon signature.
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSigOut) const;

    //! Verify a falcon signature over a 32-byte message
    static bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchPubKey);

    //! Split a buffer into two chunks, first chunk of size nFirst (never exceeds MAX_SCRIPT_ELEMENT_SIZE boundaries)
    static void SplitForScript(const std::vector<unsigned char>& vch, std::vector<unsigned char>& vch1, std::vector<unsigned char>& vch2);

    IMPLEMENT_SERIALIZE
    (
        {
            CFalconKey* pthis = const_cast<CFalconKey*>(this);
            READWRITE(pthis->vchPubKey);
            READWRITE(pthis->vchPrivKey);
            if (fRead)
                pthis->fValid = (pthis->vchPubKey.size() == PUBKEY_SIZE &&
                                 pthis->vchPrivKey.size() == PRIVKEY_SIZE);
        }
    )
};

#endif
