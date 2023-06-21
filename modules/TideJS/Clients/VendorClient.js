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
            'encryptedByGCVK': encryptedByGCVK, 
            'encryptedByGVVK': encryptedByGVVK,
            'jwt': jwt
        });
        const response = await this._post(`tide/decryptiontest`, data);
        const decryptionTest = await this._handleError(response, "Decryption Test");
        if(decryptionTest !== "Test Passed") throw Error("Decryption Test: Failed")
    }
}