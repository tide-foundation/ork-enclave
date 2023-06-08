import Point from "../Ed25519/point.js"
import { BigIntToByteArray, ConcatUint8Arrays, StringToUint8Array, base64ToBase64Url, base64ToBytes, base64UrlToBase64, bytesToBase64 } from "../Tools/Utils.js"
import { EdDSA } from "../index.js";

export default class TideJWT{
    /**
     * 
     * @param {string} uid 
     * @param {number} minutesToExpiry 
     * @param {Point} gSessKeyPub
     */
    static new(uid, minutesToExpiry, gSessKeyPub){
        const header = {
            'alg': "EdDSA",
            'typ': "JWT"
        }
        const payload = {
            'uid': uid,
            'exp': Math.floor(Date.now() / 1000) + (minutesToExpiry * 60),
            'gSessKeyPub': gSessKeyPub.toBase64()
        }
        const jwt = base64ToBase64Url(bytesToBase64(StringToUint8Array(JSON.stringify(header)))) + "." + base64ToBase64Url(bytesToBase64(StringToUint8Array(JSON.stringify(payload))));
        return jwt; // this jwt has no signature as it was just created
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
        const dataToVerify = base64ToBytes(base64UrlToBase64(strings[0] + "." + strings[1]));
        const sig = base64UrlToBase64(strings[2]);
        return await EdDSA.verify(sig, pub, dataToVerify);
    }
}