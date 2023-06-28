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

import Point from "../Ed25519/point.js"
import { BigIntToByteArray, ConcatUint8Arrays, StringToUint8Array, base64ToBase64Url, base64ToBytes, base64UrlToBase64, bytesToBase64 } from "../Tools/Utils.js"
import { EdDSA } from "../index.js";

export default class TideJWT{
    /**
     * 
     * @param {string} uid 
     * @param {number} minutesToExpiry 
     * @param {Point} gSessKeyPub
     * @param {string} gVVK
     */
    static new(uid, minutesToExpiry, gSessKeyPub, gVVK){
        const header = {
            'alg': "EdDSA",
            'typ': "JWT"
        }
        const payload = {
            'uid': uid,
            'exp': Math.floor(Date.now() / 1000) + (minutesToExpiry * 60),
            'gSessKeyPub': gSessKeyPub.toBase64(),
            'gVVK': gVVK
        }
        const jwt = base64ToBase64Url(bytesToBase64(StringToUint8Array(JSON.stringify(header)))) + "." + base64ToBase64Url(bytesToBase64(StringToUint8Array(JSON.stringify(payload))));
        return jwt; // this jwt has no signature as it was just created
    }

    static getUID(jwt){
        var p = jwt.split(".")[1];
        return JSON.parse(atob(base64UrlToBase64(p))).uid;
    }

    /**
     * 
     * @param {string} jwt 
     * @param {bigint} S 
     * @param {Point} R 
     */
    static addSignature(jwt, S, R){
        return jwt + "." + base64ToBase64Url(bytesToBase64(ConcatUint8Arrays([R.toArray(), BigIntToByteArray(S)])));
    }

    /**
     * @param {string} jwt 
     * @param {Point} pub 
     */
    static async verify(jwt, pub){
        const strings = jwt.split(".");
        const dataToVerify = StringToUint8Array(strings[0] + "." + strings[1]);
        const sig = base64UrlToBase64(strings[2]);
        return await EdDSA.verify(sig, pub, dataToVerify);
    }
}