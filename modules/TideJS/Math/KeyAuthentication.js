import Point from "../Ed25519/point.js";
import ConvertResponse from "../Models/ConvertResponse.js";
import EncryptedConvertResponse from "../Models/EncryptedConvertResponse.js";
import TideJWT from "../Models/TideJWT.js";
import { createAESKey } from "../Tools/AES.js";
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js";
import { BigIntToByteArray, Bytes2Hex, ConcatUint8Arrays, RandomBigInt, StringToUint8Array, bytesToBase64, median } from "../Tools/Utils.js";
import { BigIntFromByteArray } from "../Tools/Utils.js";
import { mod } from "../Tools/Utils.js";
import { mod_inv } from "../Tools/Utils.js";
import { AES, Utils } from "../index.js";
import { GetLi } from "./SecretShare.js";

/**
 * @param {ConvertResponse[]} convertResponses 
 * @param {Point[]} mgORKi 
 * @param {bigint[]} lis 
 * @param {bigint} r1 
 * @param {bigint} startTime 
 */
export async function PrismConvertReply(convertResponses, lis, mgORKi, r1, startTime){    
    const gPassPRISM = convertResponses.reduce((sum, next, i) => sum.add(next.GBlurPassPRISMi.times(lis[i])), Point.infinity).times(mod_inv(r1));
    const gPassPRISM_hashed = mod(BigIntFromByteArray(await SHA256_Digest(gPassPRISM.toArray())));

    const pre_prismAuthi = mgORKi.map(async ork => await SHA256_Digest(ork.times(gPassPRISM_hashed).toArray())) // create a prismAuthi for each ork
    const prismAuthis = await Promise.all(pre_prismAuthi); // wait for all async functions to finish

    const deltaTime = median(convertResponses.map(resp => resp.Timestampi)) - startTime;
    
    return {prismAuthis: prismAuthis, deltaTime: deltaTime}
}

/**
 * @param {string} id
 * @param {ConvertResponse[]} convertResponses 
 * @param {bigint[]} lis 
 * @param {Uint8Array[]} prismAuthis
 * @param {Point} gCMK 
 * @param {bigint} r2 
 * @param {bigint} deltaTime
 */
export async function CmkConvertReply(id, convertResponses, lis, prismAuthis, gCMK, r2, deltaTime){
    const pre_decData = convertResponses.map(async (resp, i) => EncryptedConvertResponse.from(await AES.decryptData(resp.EncryptedData, prismAuthis[i])));
    const decData = await Promise.all(pre_decData);

    const gUserCMK = decData.reduce((sum, next, i) => sum.add(next.GBlurUserCMKi.times(lis[i])), Point.infinity).times(mod_inv(r2));
    const gUserCMK_Hash = await SHA512_Digest(gUserCMK.toArray());

    const CMKMul = mod(BigIntFromByteArray(gUserCMK_Hash.slice(0, 32)));
    const VUID = Bytes2Hex(gUserCMK_Hash.slice(-32));
    const gCMKAuth = gCMK.times(CMKMul);
    const SessKey = RandomBigInt();
    const gSessKeyPub = Point.g.times(SessKey);
    const r4 = RandomBigInt();
    const gRMul = decData.reduce((sum, next) => sum.add(next.GCMKRi), Point.infinity).times(mod_inv(r4));
    const timestamp2 = BigInt(Math.floor(Date.now() / 1000)) + deltaTime;

    const M = await SHA256_Digest(timestamp2.toString() + gSessKeyPub.toBase64());
    const H = mod(BigIntFromByteArray(await SHA512_Digest(ConcatUint8Arrays([gRMul.toArray(), gCMKAuth.toArray(), M]))));
    const blurHCMKMuli = lis.map(li => mod(H * CMKMul * r4 * li));
    
    const pre_encAuthRequests = prismAuthis.map(async (pAuth, i) => await AES.encryptData(JSON.stringify(
        {
            'UserId': id,
            'BlurHCMKMuli':bytesToBase64(BigIntToByteArray(blurHCMKMuli[i]))
        }), pAuth));
    const encAuthRequests = await Promise.all(pre_encAuthRequests);

    // Prepare a JWT with 30 min expiration date
    const jwt = TideJWT.new(id, 30, gSessKeyPub);

    const data_for_PreSignInCVK = {
        'prismAuthis': prismAuthis,
        'r4': r4,
        'gRMul': gRMul,
        'H': H,
        'gCMKAuth': gCMKAuth,
        'SessKey': SessKey
    }

    return {VUID: VUID, encAuthRequests: encAuthRequests, timestamp2: timestamp2, jwt: jwt, gSessKeyPub: gSessKeyPub, data_for_PreSignInCVK: data_for_PreSignInCVK, decChallengei: decData.map(a => a.Challengei)}
}

/**
 * @param {string[]} encSig
 * @param {string[]} encCVKRi 
 * @param {object} data_for_PreSignInCVK 
 * @param {Point[]} vgORKi
 */
export async function PreSignInCVKReply(encSig, encCVKRi, data_for_PreSignInCVK, vgORKi){
    const pre_Si = encSig.map(async (enc, i) => BigIntFromByteArray(StringToUint8Array(await AES.decryptData(enc, data_for_PreSignInCVK.prismAuthis[i]))));
    const Si = await Promise.all(pre_Si);

    const S = mod(Si.reduce((sum, next) => sum + next) * mod_inv(data_for_PreSignInCVK.r4));

    const _8 = BigInt(8);
    const hash_CMKAuth = mod(BigIntFromByteArray(await SHA256_Digest("CMK authentication")));
    if(!(Point.g.times(S).times(_8).isEqual(data_for_PreSignInCVK.gRMul.times(_8).add(data_for_PreSignInCVK.gCMKAuth.times(data_for_PreSignInCVK.H).times(_8).times(hash_CMKAuth))))){
        throw new Error("Blind signature failed");
    }

    const pre_ECDHi = vgORKi.map(async pub => await SHA256_Digest(pub.times(data_for_PreSignInCVK.SessKey).toArray()));
    const ECDHi = await Promise.all(pre_ECDHi);

    const pre_gCVKRi = encCVKRi.map(async (enc, i) => Point.fromB64(await AES.decryptData(enc, ECDHi[i])));
    const gCVKRi = await Promise.all(pre_gCVKRi);
    const gCVKR = gCVKRi.reduce((sum, next) => sum.add(next));

    return {gCVKR: gCVKR, S: S, ECDHi: ECDHi}
}

/**
 * 
 * @param {string[]} encCVKSign 
 * @param {Point} gCVKR 
 * @param {string} jwt 
 * @param {Uint8Array[]} ECDHi 
 */
export async function SignInCVKReply(encCVKSign, gCVKR, jwt, ECDHi){
    const pre_CVKSi = encCVKSign.map(async (enc, i) => BigIntFromByteArray(StringToUint8Array(await AES.decryptData(enc, ECDHi[i]))));
    const CVKSi = await Promise.all(pre_CVKSi);
    const CVKS = mod(CVKSi.reduce((sum, next) => sum + next));

    return TideJWT.addSignature(jwt, CVKS, gCVKR);
}