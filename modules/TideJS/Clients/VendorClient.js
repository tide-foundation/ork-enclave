import Point from "../Ed25519/point";
import ClientBase from "./ClientBase";

export default class VendorClient extends ClientBase{
    /**
     * @param {string} url 
     */
    constructor(url){
        super(url);
    }

    /**
     * 
     * @param {string} encryptedByGCVK 
     * @param {string} encryptedByGVVK 
     * @param {string} jwt 
     */
    async DecryptionTest(encryptedByGCVK, encryptedByGVVK, jwt){
        const data = this._createFormData({ 
            'encryptedByGCVK': encryptedData, 
            'encryptedByGVVK': gSessKeyPub.toBase64(),
            'jwt': jwt
        });
        const response = this._post(`tidetest`, data);

    }
}