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
import { AES, Utils } from "../index.js";
import { SHA256_Digest } from "./Hash.js";
import { ConcatUint8Arrays, RandomBigInt, XOR, base64ToBytes, bytesToBase64 } from "./Utils.js";

export default class ElGamal{
    /**
     * 
     * @param {Uint8Array} secretData 
     * @param {Point} publicKey 
     */
    static async encryptData(secretData, publicKey){
        const r = RandomBigInt();
        const c1 = Point.g.times(r).toArray();
        var c2;
        if(secretData.length <= 32){
            const padded_secret = Utils.PadRight(secretData, 32);
            const length_byte = new Uint8Array([secretData.length]);
            const version_byte = new Uint8Array([0]); // no versioning yet
            c2 = ConcatUint8Arrays([version_byte, length_byte, XOR(padded_secret, await SHA256_Digest(publicKey.times(r).toArray()))])
        }
        else{
            c2 = base64ToBytes(await AES.encryptData(secretData, await SHA256_Digest(publicKey.times(r).toArray())));
        }
        return bytesToBase64(ConcatUint8Arrays([c1, c2]));
    }
}