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
import PrismFlow from "../Flow/Prism.js"
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray, BigIntToByteArray, Bytes2Hex, mod, mod_inv, RandomBigInt } from "../Tools/Utils.js"
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js"
import { createAESKey, encryptData } from "../Tools/AES.js"
import SignIn from "./SignIn.js"
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow.js"
import TideJWT from "../Models/TideJWT.js"

export default class SignUp {
    /**
     * Config should include key/value pairs of: 
     * @example
     * {
     *  cmkOrkInfo: [string, string Point][]
     *  cvkOrkInfo: [string, string Point][]
     *  simulatorUrl: string  
     * }
     * @example
     * @param {object} config 
     */
    constructor(config) {
        if (!Object.hasOwn(config, 'cmkOrkInfo')) { throw Error("CMK OrkInfo has not been included in config") }
        if (!Object.hasOwn(config, 'cvkOrkInfo')) { throw Error("CVK OrkInfo has not been included in config") }
        if (!Object.hasOwn(config, 'simulatorUrl')) { throw Error("Simulator Url has not been included in config") }

        /**
         * @type {[string, string, Point][]}
         */
        this.cmkOrkInfo = config.cmkOrkInfo
        /**
         * @type {[string, string, Point][]}
         */
        this.cvkOrkInfo = config.cvkOrkInfo
        /**
         * @type {string}
         */
        this.simulatorUrl = config.simulatorUrl
    }

    /**
     * 
     * @param {string} username 
     * @param {string} password 
     * @param {string} gVVK The vendor's public key
     */
    async start(username, password, gVVK) {
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        const r1 = RandomBigInt();
        const r2 = RandomBigInt();

        const gUser = await Point.fromString(username.toLowerCase() + gVVK);
        const gBlurUser = gUser.times(r1);
        //convert password to point
        const gPass = await Point.fromString(password);
        const gBlurPass = gPass.times(r2);

        // Start Key Generation Flow
        const cmkGenFlow = new dKeyGenerationFlow(this.cmkOrkInfo);
        const cmkGenShardData = await cmkGenFlow.GenShard(uid, 2);  // GenShard
        const cmkSendShardData = await cmkGenFlow.SendShard(uid, cmkGenShardData.sortedShares, cmkGenShardData.R2, [gBlurUser, gBlurPass], cmkGenShardData.timestamp);   
        
        const {gPRISMAuth, VUID, gCMKAuth} = await this.getKeyPoints(cmkSendShardData.gMultiplied, [r1, r2], cmkSendShardData.GK1);

        const cvkGenFlow = new dKeyGenerationFlow(this.cvkOrkInfo);
        const cvkGenShardData = await cvkGenFlow.GenShard(VUID, 1);
        const cvkSendShardData = await cvkGenFlow.SendShard(VUID, cvkGenShardData.sortedShares, cvkGenShardData.R2, [], cvkGenShardData.timestamp, gCMKAuth);

        // Test sign in
        const jwt = await this.testSignIn(username, password, Point.fromB64(gVVK), cmkSendShardData.GK1, cvkSendShardData.GK1);

        const pre_cmkCommit = cmkGenFlow.Commit(uid, cmkSendShardData.S, cmkSendShardData.encCommitStatei, gPRISMAuth);
        const pre_cvkCommit = cvkGenFlow.Commit(VUID, cvkSendShardData.S, cvkSendShardData.encCommitStatei);

        await pre_cmkCommit;
        await pre_cvkCommit;

        return jwt;
    }

    /**
     * 
     * @param {string} username 
     * @param {string} password 
     * @param {Point} gVVK 
     * @param {Point} cmkPub 
     * @param {Point} cvkPub 
     * @returns 
     */
    async testSignIn(username, password, gVVK, cmkPub, cvkPub){
        const startTime = BigInt(Math.floor(Date.now() / 1000));
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));


        const gUser = await Point.fromString(username.toLowerCase() + gVVK.toBase64());
        const gBlurUser = gUser.times(r2);
        //convert password to point
        const gPass = await Point.fromString(password);
        const gBlurPass = gPass.times(r1);


        const authFlow = new dKeyAuthenticationFlow(this.cmkOrkInfo);
        const convertData = await authFlow.Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, cmkPub);
        
        authFlow.CVKorks = this.cvkOrkInfo;
        const authData = await authFlow.Authenticate_and_PreSignInCVK(uid, convertData.VUID, convertData.decChallengei, convertData.encAuthRequests, convertData.gSessKeyPub, convertData.data_for_PreSignInCVK);

        const jwt = await authFlow.SignInCVK(convertData.VUID, convertData.jwt, authData.vlis, convertData.timestamp2, convertData.data_for_PreSignInCVK.gRMul, authData.gCVKR, authData.S, authData.ECDHi);
        if(!(await TideJWT.verify(jwt, cvkPub))) throw Error("Test sign in failed");
        return jwt;
    }

    /**
     * 
     * @param {Point[]} gMultiplied 
     * @param {bigint[]} r 
     * @param {Point} gCMK
     */
    async getKeyPoints(gMultiplied, r, gCMK){
        const gUserCMK = gMultiplied[0].times(mod_inv(r[0]));
        const gPassPRISM = gMultiplied[1].times(mod_inv(r[1]));

        const gPRISMAuth = Point.g.times(BigIntFromByteArray(await SHA256_Digest(gPassPRISM.toArray())));
        const hashed_gUserCMK = await SHA512_Digest(gUserCMK.toArray());

        const VUID = Bytes2Hex(hashed_gUserCMK.slice(-32)); 
        const CMKMul = mod(BigIntFromByteArray(hashed_gUserCMK.slice(0, 32)));
        const gCMKAuth = gCMK.times(CMKMul);

        return {VUID: VUID, gCMKAuth: gCMKAuth, gPRISMAuth: gPRISMAuth}
    }
}
