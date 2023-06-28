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
        const gBlurPassPRISMi = Point.fromB64(obj.GBlurPassPrism)
        return new ConvertResponse(obj.EncryptedData, gBlurPassPRISMi, timestampi);
    }
}