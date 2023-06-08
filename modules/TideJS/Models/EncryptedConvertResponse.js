import Point from "../Ed25519/point.js";

export default class EncryptedConvertResponse{
    /** 
     * @param {string} Challengei
     * @param {Point} GBlurUserCMKi
     * @param {Point} GCMKRi 
     */
    constructor(Challengei, GBlurUserCMKi, GCMKRi){
        this.Challengei = Challengei
        this.GBlurUserCMKi = GBlurUserCMKi
        this.GCMKRi = GCMKRi
    }
    static from(data){
        const obj = JSON.parse(data);
        const gBlurUserCMKi= Point.fromB64(obj.GBlurUserCMKi)
        const gCMKRi = Point.fromB64(obj.GCMKRi)
        return new EncryptedConvertResponse(obj.Challengei, gBlurUserCMKi, gCMKRi);
    }
}