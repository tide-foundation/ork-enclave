import VendorClient from "../Clients/VendorClient.js";
import Point from "../Ed25519/point.js";
import { encrypt_ElGamal } from "../Tools/ElGamal.js";

export default class dDecryptionTestFlow{
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

        const vendorClient = new VendorClient(this.vendorUrl);
        await vendorClient.DecryptionTest(encryptedByGCVK, encryptedByGVVK, this.jwt);
    }
}