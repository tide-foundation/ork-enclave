import Point from "../Ed25519/point.js";
import ClientBase from "./ClientBase.js";

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
     * @param {string} cvkOrkUrl
     */
    async DecryptionTest(encryptedByGCVK, encryptedByGVVK, jwt, cvkOrkUrl){
        const data = this._createFormData({ 
            'encryptedByGCVK': encryptedByGCVK, 
            'encryptedByGVVK': encryptedByGVVK,
            'jwt': jwt,
            'cvkOrkUrl': cvkOrkUrl
        });
        const response = await this._post(`tide/decryptiontest`, data);
        const decryptionTest = await this._handleError(response, "Decryption Test");
        if(decryptionTest !== "Test Passed") throw Error("Decryption Test: Failed")
    }
}