// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import Point from "../Ed25519/point.js";
import AuthenticateResponse from "../Models/AuthenticateResponse.js";
import ConvertResponse from "../Models/ConvertResponse.js";
import EncryptedConvertResponse from "../Models/EncryptedConvertResponse.js";
import PreSignInResponse from "../Models/PreSignInResponse.js";
import SignInResponse from "../Models/SignInResponse.js";
import TideJWT from "../ModelsToSign/TideJWT.js";
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
 * @param {string} gVVK
 */
export async function CmkConvertReply(id, convertResponses, lis, prismAuthis, gCMK, r2, deltaTime, gVVK){
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
    const jwt = TideJWT.new(VUID, 30, gSessKeyPub, gVVK);

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
 * @param {string[]} encGRData 
 * @param {object} data_for_PreSignInCVK 
 * @param {Point[]} vgORKi
 */
export async function PreSignInCVKReply(encSig, encGRData, data_for_PreSignInCVK, vgORKi){
    let pre_authResp;
    try{
        pre_authResp = encSig.map(async (enc, i) => AuthenticateResponse.from(await AES.decryptData(enc, data_for_PreSignInCVK.prismAuthis[i])));
    }catch{
        throw Error("Wrong password");
    } 
    const authResp = await Promise.all(pre_authResp);

    const mod_inv_r4 = mod_inv(data_for_PreSignInCVK.r4);
    const S = mod(authResp.reduce((sum, next) => sum + next.Si, BigInt(0)) * mod_inv_r4);
    const gBlindH = authResp.reduce((sum, next) => sum.add(next.gBlindH), Point.infinity).times(mod_inv_r4);

    const _8 = BigInt(8);
    const hash_CMKAuth = mod(BigIntFromByteArray(await SHA256_Digest("CMK authentication")));
    if(!(Point.g.times(S).times(_8).isEqual(data_for_PreSignInCVK.gRMul.times(_8).add(data_for_PreSignInCVK.gCMKAuth.times(data_for_PreSignInCVK.H).times(_8)).add(gBlindH.times(hash_CMKAuth).times(_8))))){
        throw new Error("Blind signature failed");
    }

    const pre_ECDHi = vgORKi.map(async pub => await SHA256_Digest(pub.times(data_for_PreSignInCVK.SessKey).toArray()));
    const ECDHi = await Promise.all(pre_ECDHi);

    const pre_gRs = encGRData.map(async (enc, i) => PreSignInResponse.from(await AES.decryptData(enc, ECDHi[i])));
    const gRs = await Promise.all(pre_gRs);
    const gCVKR = gRs.reduce((sum, next) => sum.add(next.GR1), Point.infinity);
    const model_gR = gRs.every(gr => gr.GR2 != null) ? gRs.reduce((sum, next) => sum.add(next.GR2), Point.infinity) : null;

    return {gCVKR: gCVKR, model_gR: model_gR, S: S, ECDHi: ECDHi, gBlindH: gBlindH}
}

/**
 * 
 * @param {string[]} encSigs 
 * @param {Point} modelR
 * @param {Point} gCVKR 
 * @param {string} jwt 
 * @param {Uint8Array[]} ECDHi 
 * @param {bigint[]} vLis
 */
export async function SignInCVKReply(encSigs, gCVKR, modelR, jwt, ECDHi, vLis){
    const pre_Sigs = encSigs.map(async (enc, i) => SignInResponse.from(await AES.decryptData(enc, ECDHi[i])));
    const Sigs = await Promise.all(pre_Sigs);
    const CVKS = mod(Sigs.reduce((sum, next, i) => sum + (next.S1 * vLis[i]), BigInt(0)));
    const model_S = Sigs.every(s => s.S2 != null) ? mod(Sigs.reduce((sum, next, i) => sum + (next.S2 * vLis[i]), BigInt(0))) : null;
    const modelSig = model_S != null ? bytesToBase64(ConcatUint8Arrays([modelR.toArray(), BigIntToByteArray(model_S)])) : null;

    return {jwt: TideJWT.addSignature(jwt, CVKS, gCVKR), modelSig: modelSig};
}