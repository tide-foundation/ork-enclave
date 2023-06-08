import Point from "../Ed25519/point.js";

export default class ConvertResponse{
    /** 
     * @param {string} EncryptedData
     * @param {Point} GBlurPassPRISMi
     * @param {bigint} Timestampi 
     */
    constructor(EncryptedData, GBlurPassPRISMi, Timestampi){
        this.EncryptedData = EncryptedData
        this.GBlurPassPRISMi = GBlurPassPRISMi
        this.Timestampi = Timestampi
    }
    static from(data){
        const obj = JSON.parse(data);
        const timestampi = BigInt(obj.Timestampi);
        const gBlurPassPRISMi = Point.fromB64(obj.GBlurPassPRISMi)
        return new ConvertResponse(obj.EncryptedData, gBlurPassPRISMi, timestampi);
    }
}