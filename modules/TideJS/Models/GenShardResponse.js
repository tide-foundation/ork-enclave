// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

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