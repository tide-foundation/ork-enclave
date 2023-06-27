import Point from "../Ed25519/point.js";

export default class AuthenticateResponse{
    /**
     * 
     * @param {bigint} Si 
     * @param {Point} gBlindH 
     */
    constructor(Si, gBlindH){
        this.Si = Si
        this.gBlindH = gBlindH
    }

    static from(data){
        const obj = JSON.parse(data);
        const si = BigInt(obj.Si)
        const gBlindH = Point.fromB64(obj.gBlindHi)
        return new AuthenticateResponse(si, gBlindH)
    }
}