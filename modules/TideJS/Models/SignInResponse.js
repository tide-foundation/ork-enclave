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

export default class SignInResponse{
    /** 
     * @param {bigint} S1
     * @param {bigint} S2
     */
    constructor(S1, S2){
        this.S1 = S1
        this.S2 = S2
    }
    static from(data){
        const obj = JSON.parse(data);
        const s1 = BigInt(obj.S1)
        const s2 = obj.S2 != null ? BigInt(obj.S2) : null;
        return new SignInResponse(s1, s2);
    }
}