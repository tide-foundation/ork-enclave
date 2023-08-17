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
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray, BigIntToByteArray, Bytes2Hex, mod, mod_inv, RandomBigInt } from "../Tools/Utils.js"
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js"
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow.js"
import TideJWT from "../ModelsToSign/TideJWT.js"
import dDecryptionTestFlow from "../Flow/dDecryptionTestFlow.js"
import HashToPoint from "../Tools/H2P.js"

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

        /**
         * @type {string}
         */
        this.mode = Object.hasOwn(config, 'mode') ? config.mode : "default";

        /**
         * @type {string}
         */
        this.modelToSign = Object.hasOwn(config, 'modelToSign') ? config.modelToSign : null;

        this.savedState = undefined;
    }

    /**
     * 
     * @param {string} username 
     * @param {string} password 
     * @param {string} gVVK The vendor's public key
     * @param {string} vendorUrl
     */
    async start(username, password, gVVK, vendorUrl) { // should we implement a vendor object where the VVK signs the vendorUrl + homeOrk url?
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        const r1 = RandomBigInt();
        const r2 = RandomBigInt();

        const gUser = await HashToPoint(username.toLowerCase() + gVVK);
        const gBlurUser = gUser.times(r1);
        //convert password to point
        const gPass = await HashToPoint(password);
        const gBlurPass = gPass.times(r2);

        // Start Key Generation Flow
        const cmkGenFlow = new dKeyGenerationFlow(this.cmkOrkInfo);
        const cmkGenShardData = await cmkGenFlow.GenShard(uid, 2, [gBlurUser, gBlurPass]);  // GenShard

        const {gPRISMAuth, VUID, gCMKAuth} = await this.getKeyPoints(cmkGenShardData.gMultiplied, [r1, r2], cmkGenShardData.gK1);

        const pre_cmkSendShardData = cmkGenFlow.SendShard(uid, cmkGenShardData.sortedShares, cmkGenShardData.R2, cmkGenShardData.timestamp, gPRISMAuth, "CMK", cmkGenShardData.gK1);  // async SendShard

        const cvkGenFlow = new dKeyGenerationFlow(this.cvkOrkInfo);
        const cvkGenShardData = await cvkGenFlow.GenShard(VUID, 1, []);
        const cvkSendShardData = await cvkGenFlow.SendShard(VUID, cvkGenShardData.sortedShares, cvkGenShardData.R2, cvkGenShardData.timestamp, gCMKAuth, "CVK", cvkGenShardData.gK1);

        const cmkSendShardData = await pre_cmkSendShardData;

        this.savedState = {
            uid: uid,
            VUID: VUID,
            gUser: gUser,
            gPass: gPass,
            gVVK: gVVK,
            cmkPub: cmkGenShardData.gK1,
            cvkPub: cvkGenShardData.gK1,
            vendorUrl: vendorUrl,
            cmkSig: cmkSendShardData.S,
            cvkSig: cvkSendShardData.S,
            cmkFlow: cmkGenFlow,
            cvkFlow: cvkGenFlow
        }

        // end here
        return {
            ok: true,
            dataType: "userData",
            newAccount: true, // needed for when sign in ALSO creates CVKs
            publicKey: cvkGenShardData.gK1.toBase64(),
            uid: VUID
        };
    }

    async continue(modelToSign=null){
        if(this.savedState == undefined) throw Error("Saved state not defined");
        if(modelToSign == null && this.modelToSign == null) this.mode = "default"; // revert mode to default if no model to sign provided

        // Test sign in
        const {jwt, modelSig} = await this.testSignIn(this.savedState.uid, this.savedState.gUser, this.savedState.gPass, this.savedState.gVVK, this.savedState.cmkPub, this.savedState.cvkPub, modelToSign);

        // Test dDecrypt
        if(this.mode == "default"){
            // implement flag for which tests we want to run in new account
            //       const dDecryptFlow = new dDecryptionTestFlow(this.savedState.vendorUrl, Point.fromB64(this.savedState.gVVK), this.savedState.cvkPub, jwt, this.cvkOrkInfo[0][1]); // send first cvk ork's url as cvkOrkUrl, randomise in future?
        //         await dDecryptFlow.startTest();
        }

        // Commit newly generated keys
        const pre_cmkCommit = this.savedState.cmkFlow.Commit(this.savedState.uid, this.savedState.cmkSig, "CMK");
        const pre_cvkCommit = this.savedState.cvkFlow.Commit(this.savedState.VUID, this.savedState.cvkSig, "CVK");

        await pre_cmkCommit;
        await pre_cvkCommit;

        return {
            ok: true,
            dataType: "completed",
            TideJWT: jwt, 
            modelSig: modelSig
        };
    }

    /**
     * @param {string} uid
     * @param {Point} gUser 
     * @param {Point} gPass 
     * @param {string} gVVK 
     * @param {Point} cmkPub 
     * @param {Point} cvkPub 
     * @param {string} modelToSign
     * @returns 
     */
    async testSignIn(uid, gUser, gPass, gVVK, cmkPub, cvkPub, modelToSign_p=null){
        const modelRequested = (this.modelToSign == null && modelToSign_p == null) ? false : true;
        const modelToSign = this.modelToSign == null ? modelToSign_p : this.modelToSign; // figure out which one is the not null, if both are null, it will still be null

        const startTime = BigInt(Math.floor(Date.now() / 1000));
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();

        const gBlurUser = gUser.times(r2);
        
        const gBlurPass = gPass.times(r1);

        const authFlow = new dKeyAuthenticationFlow(this.cmkOrkInfo);
        const convertData = await authFlow.Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, cmkPub, gVVK, true);
        
        authFlow.CVKorks = this.cvkOrkInfo;
        const authData = await authFlow.Authenticate_and_PreSignInCVK(uid, convertData.VUID, convertData.decChallengei, convertData.encAuthRequests, convertData.gSessKeyPub, convertData.data_for_PreSignInCVK, modelRequested, true);

        const resp = await authFlow.SignInCVK(convertData.VUID, convertData.jwt, authData.vlis, convertData.timestamp2, convertData.data_for_PreSignInCVK.gRMul, authData.gCVKR, authData.S, authData.ECDHi, authData.gBlindH, this.mode, modelToSign, authData.model_gR, true);
        if(!(await TideJWT.verify(resp.jwt, cvkPub))) throw Error("Test sign in failed");
        return resp;
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
