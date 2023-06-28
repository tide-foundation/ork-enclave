import Point from "../Ed25519/point.js"

export default class GenShardResponse{
    /** 
     * @param {string[]} YijCiphers 
     * @param {Point} GRi
     * @param {bigint} Timestampi 
     * @param {Point[]} GMultiplied
     * @param {Point} GK1i
     */
    constructor(YijCiphers, GRi, Timestampi, GMultiplied, GK1i){
        this.YijCiphers = YijCiphers
        this.GRi = GRi
        this.Timestampi = Timestampi
        this.GMultiplied = GMultiplied
        this.GK1i = GK1i
    }
    static from(data){
        const obj = JSON.parse(data);
        const timestampi = BigInt(obj.Timestampi);
        const gRi = Point.fromB64(obj.GRi)
        const gMultiplied = obj.GMultiplied.map(p => p == null ? null : Point.fromB64(p));
        const gK1i = Point.fromB64(obj.GK1i);
        return new GenShardResponse(obj.YijCiphers, gRi, timestampi, gMultiplied, gK1i);
    }
}