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
import { SHA256_Digest } from "../Tools/Hash.js"
import { BigIntToByteArray, Bytes2Hex, RandomBigInt, bytesToBase64, getCSharpTime } from "../Tools/Utils.js"
import SimulatorClient from "../Clients/SimulatorClient.js"
import NodeClient from "../Clients/NodeClient.js"
import { decryptData } from "../Tools/AES.js"
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow.js"
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js"
import HashToPoint from "../Tools/H2P.js"
import TestSignIn from "./TestSignIn.js"
import KeyInfo from "../Models/KeyInfo.js"
import OrkInfo from "../Models/OrkInfo.js"

export default class SignIn {
    /**
     * Config should include key/value pairs of: 
     * @example
     * {
     *  mode: string // what type of service are you signing up to (e.g. an OpenSSH server - "openssh"). If you aren't sure, don't include this field or set it to "default"
     *  modelToSign: string // string representation of what you want to sign in this process. TODO: Clarify to user how this process works
     * }
     * @example
     * @param {object} config 
     */
    constructor(config) {

        /**
         * @type {string}
         */
        this.mode = Object.hasOwn(config, 'mode') ? config.mode : "default";

        /**
         * @type {string}
         */
        this.modelToSign = Object.hasOwn(config, 'modelToSign') ? config.modelToSign : null;

        this.savedState = {}

        this.authFlow = undefined
        this.convertData = undefined
        this.uid = undefined
        this.cvkExists = undefined
    }

    /**
     * Authenticates a user to the ORKs and decrypts their encrypted secret held by vendor.
     * @param {string} username 
     * @param {string} password 
     * @param {string} gVVK The vendor's public key
     */
    async start(username, password, gVVK) {
        const startTime = BigInt(Math.floor(Date.now() / 1000));
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        // Putting this up here to speed things up using await
        const simClient = new SimulatorClient();
        const pre_keyInfo = simClient.GetKeyInfo(uid);

        const gUser = await HashToPoint(username.toLowerCase() + gVVK);
        const gBlurUser = gUser.times(r2);
        //convert password to point
        const gPass = await HashToPoint(password);
        const gBlurPass = gPass.times(r1);

        // get key info
        const cmkInfo = await pre_keyInfo;

        const authFlow = new dKeyAuthenticationFlow(cmkInfo.orkInfo, true, true, true);
        const convertData = await authFlow.Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, cmkInfo.keyPublic, gVVK);

        let cvkInfo;
        try{
            cvkInfo = await simClient.GetKeyInfo(convertData.VUID);
            this.cvkExists = true;
        }catch{
            // key for VUID was not found
            this.cvkExists = false;
        }

        if(this.cvkExists ==  false) {
            this.savedState.uid = uid;
            this.savedState.VUID = convertData.VUID;
            this.savedState.gVVK = gVVK;
            this.savedState.gUser = gUser;
            this.savedState.gPass = gPass;
            this.savedState.cmkOrkInfo = cmkInfo.orkInfo;
            this.savedState.cmkPub = cmkInfo.keyPublic;
            return await this.createCVK(convertData.VUID, convertData.data_for_PreSignInCVK.gCMKAuth, cmkInfo.orkInfo); // cvk orks are the same as cmk orks for now HERE
        }

        this.savedState = {
            authFlow: authFlow,
            convertData: convertData,
            uid: uid,
            cvkInfo: cvkInfo
        }

        return {
            ok: true,
            dataType: "userData",
            newAccount: false,
            publicKey: cvkInfo.keyPublic.toBase64(),
            uid: convertData.VUID
        };
    }

    async continue(modelToSign_p=null){
        if(this.cvkExists == undefined) throw Error("SignIn methods implemented improperly");
        if(this.cvkExists) return this.continueSignIn(modelToSign_p);
        else if(this.cvkExists == false) return this.commitCVK(modelToSign_p);
        else throw Error("Strange error occured")
    }

    /**
     * CMK exists for this user but no CVK for this vendor. Let's create one.
     * @param {string} VUID 
     * @param {Point} gCMKAuth
     * @param {OrkInfo[]} cvkOrkInfo 
     */
    async createCVK(VUID, gCMKAuth, cvkOrkInfo){
        const cvkGenFlow = new dKeyGenerationFlow(cvkOrkInfo);
        const cvkGenShardData = await cvkGenFlow.GenShard(VUID, 1, []);
        const cvkSendShardData = await cvkGenFlow.SendShard(VUID, cvkGenShardData.sortedShares, cvkGenShardData.R2, cvkGenShardData.timestamp, gCMKAuth, "CVK", cvkGenShardData.gK1);

        this.savedState.cvkPub = cvkGenShardData.gK1;
        this.savedState.cvkFlow = cvkGenFlow;
        this.savedState.cvkSig = cvkSendShardData.S;

        return {
            ok: true,
            dataType: "userData",
            newAccount: true,
            publicKey: cvkGenShardData.gK1.toBase64(),
            uid: VUID
        };
    }

    async continueSignIn(modelToSign_p=null){
        if(!this.savedState.authFlow || !this.savedState.convertData) throw Error("No authflow/convertData available in saved state"); // use this to determine not only if savedState exists, but also for VUID (from createCVK process)
        if(modelToSign_p == null && this.modelToSign == null) this.mode = "default"; // revert mode to default if no model to sign provided

        const modelRequested = (this.modelToSign == null && modelToSign_p == null) ? false : true;
        const modelToSign = this.modelToSign == null ? modelToSign_p : this.modelToSign; // figure out which one is the not null, if both are null, it will still be null

        this.savedState.authFlow.CVKorks = this.savedState.cvkInfo.orkInfo;
        const authData = await this.savedState.authFlow.Authenticate_and_PreSignInCVK(this.savedState.uid, this.savedState.convertData.VUID, this.savedState.convertData.decChallengei, 
            this.savedState.convertData.encAuthRequests, this.savedState.convertData.gSessKeyPub, this.savedState.convertData.data_for_PreSignInCVK, modelRequested);

        const {jwt, modelSig} = await this.savedState.authFlow.SignInCVK(this.savedState.convertData.VUID, this.savedState.convertData.jwt, 
            authData.vlis, this.savedState.convertData.timestamp2, this.savedState.convertData.data_for_PreSignInCVK.gRMul, authData.gCVKR, authData.S, authData.ECDHi, 
            authData.gBlindH, this.mode, modelToSign, authData.model_gR);
        
        return {
            ok: true,
            dataType: "completed",
            TideJWT: jwt, 
            modelSig: modelSig
        };
    }

    async commitCVK(modelToSign_p=null){
        if(!this.savedState.VUID) throw Error("No VUID available in saved state"); // use this to determine not only if savedState exists, but also for VUID (from createCVK process)
        if(modelToSign_p == null && this.modelToSign == null) this.mode = "default"; // revert mode to default if no model to sign provided

        const testSignIn = new TestSignIn(this.savedState.cmkOrkInfo, this.savedState.cmkOrkInfo, true, false, true); // send cmkOrkInfo twice as there is no vendor selection of CVK orks yet
        await testSignIn.start(this.savedState.uid, this.savedState.gUser, this.savedState.gPass, this.savedState.gVVK,
            this.savedState.cmkPub, this.savedState.cvkPub, modelToSign_p);
        const {jwt, modelSig} = testSignIn.continue(this.mode, modelToSign_p);
        
        // test dDecrypt() ?

        await this.savedState.cvkFlow.Commit(this.savedState.VUID, this.savedState.cvkSig, "CVK");

        return {
            ok: true,
            dataType: "completed",
            TideJWT: jwt, 
            modelSig: modelSig
        };
    }
}
