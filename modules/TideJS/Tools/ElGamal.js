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
        if(secretData.length < 32){
            const padded_secret = Utils.PadRight(secretData, 32);
            const length_byte = new Uint8Array([secretData.length]);
            const version_byte = new Uint8Array([0]); // no versioning yet
            c2 = ConcatUint8Arrays([version_byte, length_byte, XOR(padded_secret, await SHA256_Digest(publicKey.times(r).toArray()))])
        }
        else{
            c2 = base64ToBytes(AES.encryptData(secretData, await SHA256_Digest(publicKey.times(r).toArray())));
        }
        return bytesToBase64(ConcatUint8Arrays([c1, c2]));
    }
}