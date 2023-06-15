import Point from "../Ed25519/point";
import { encryptData } from "../Tools/AES";
import { encrypt_ElGamal } from "../Tools/ElGamal";
import { SHA256_Digest } from "../Tools/Hash";
import { ConcatUint8Arrays, RandomBigInt, base64ToBytes, bytesToBase64 } from "../Tools/Utils";

export default class dDecryptionFlow{
    /**
     * @param {string} vendorUrl 
     * @param {Point} vendorPublic
     * @param {Point} userPublic
     * @param {string} userAuthJwt 
     */
    constructor(vendorUrl, vendorPublic, userPublic, userAuthJwt){
        this.vendorUrl = vendorUrl;
        this.vendorPublic = vendorPublic;
        this.userPublic = userPublic;
        this.jwt = userAuthJwt;
    }

    async startTest(){
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);
        const encryptedByGCVK = await encrypt_ElGamal(challenge, this.userPublic);
        const encryptedByGVVK = await encrypt_ElGamal(challenge, this.vendorPublic);
    }
}