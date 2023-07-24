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

import NodeClient from "../Clients/NodeClient.js";
import Point from "../Ed25519/point.js";
import { CmkConvertReply, PreSignInCVKReply, PrismConvertReply, SignInCVKReply } from "../Math/KeyAuthentication.js";
import { GetLi } from "../Math/SecretShare.js";
import ConvertResponse from "../Models/ConvertResponse.js";

export default class dKeyAuthenticationFlow{
    /**
     * @param {[string, string, Point][]} CMKorks 
     */
    constructor(CMKorks) {
        /**
         * @type {[string, string, Point][]}  // everything about CMK orks of this user - orkID, orkURL, orkPublic
         */
        this.CMKorks = CMKorks;
        this.threshold = 2;
    }

    /**
     * 
     * @param {string} uid 
     * @param {Point} gBlurUser 
     * @param {Point} gBlurPass 
     * @param {bigint} r1 
     * @param {bigint} r2
     * @param {bigint} startTime
     * @param {Point} gCMK
     * @param {string} gVVK
     * @param {boolean} test
     */
    async Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, gCMK, gVVK, test=false){
        const clients = this.CMKorks.map(ork => new NodeClient(ork[1])) // create node clients

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map(client => client.Convert(uid, gBlurUser, gBlurPass, test));
        const settledPromises = await Promise.allSettled(pre_ConvertResponses);// determine which promises were fulfilled
        var activeOrks = []
        settledPromises.forEach((promise, i) => {
            if(promise.status === "fulfilled") activeOrks.push(this.CMKorks[i]) // create new ork list on orks which replied
        }); 
        if(activeOrks.length < this.threshold){
            // @ts-ignore
            if(settledPromises.filter(promise => promise.status === "rejected").some(promise => promise.reason === "Too many attempts")) throw new Error("Too many attempts")
            else throw new Error("CMK Orks for this account are down");
        } 
        this.CMKorks = activeOrks;

        // Generate lis for CMKOrks based on the ones that replied
        const ids = this.CMKorks.map(ork => BigInt(ork[0])); // create lis for all orks that responded
        const lis = ids.map(id => GetLi(id, ids, Point.order));

        /**@type {ConvertResponse[]} */
        // @ts-ignore
        const ConvertResponses = settledPromises.filter(promise => promise.status === "fulfilled").map(promise => promise.value); // .value will exist here as we have filtered the responses above
        
        const {prismAuthis, deltaTime} = await PrismConvertReply(ConvertResponses, lis, this.CMKorks.map(c => c[2]), r1, startTime);
        return await CmkConvertReply(uid, ConvertResponses, lis, prismAuthis, gCMK, r2, deltaTime, gVVK);
    }

    /**
     * 
     * @param {string} uid 
     * @param {string} vuid
     * @param {string[]} decryptedChallengei 
     * @param {string[]} encryptedAuthRequest 
     * @param {Point} gSessKeyPub
     * @param {object} data_for_PreSignInCVK
     * @param {boolean} modelRequested
     * @param {boolean} test
     */
    async Authenticate_and_PreSignInCVK(uid, vuid, decryptedChallengei, encryptedAuthRequest, gSessKeyPub, data_for_PreSignInCVK, modelRequested=false, test=false){
        const cmkClients = this.CMKorks.map(ork => new NodeClient(ork[1]))
        const cvkClients = this.CVKorks.map(ork => new NodeClient(ork[1]))

        const pre_encSig = cmkClients.map((client, i) => client.Authenticate(uid, decryptedChallengei[i], encryptedAuthRequest[i], test))
        const pre_encGRData = cvkClients.map(client => client.PreSignInCVK(vuid, gSessKeyPub, modelRequested));

        const encSig = await Promise.all(pre_encSig);

        // Determine which CVK orks responded
        const settledPromises = await Promise.allSettled(pre_encGRData);// determine which promises were fulfilled
        var activeOrks = []
        settledPromises.forEach((promise, i) => {
            if(promise.status === "fulfilled") activeOrks.push(this.CVKorks[i]) // create new ork list on orks which replied
        }); 
        if(activeOrks.length < this.threshold){
            // @ts-ignore
            if(settledPromises.filter(promise => promise.status === "rejected").some(promise => promise.reason === "Too many attempts")) throw new Error("Too many attempts")
            else throw new Error("CVK Orks for this account are down");
        } 
        this.CVKorks = activeOrks;

        // Generate lis for CVKOrks based on the ones that replied
        const vids = this.CVKorks.map(ork => BigInt(ork[0])); 
        const vlis = vids.map(id => GetLi(id, vids, Point.order));

        /**@type {string[]} */
        // @ts-ignore
        const encGRData = settledPromises.filter(promise => promise.status === "fulfilled").map(promise => promise.value); // .value will exist here as we have filtered the responses above
      
        return {
            ... await PreSignInCVKReply(encSig, encGRData, data_for_PreSignInCVK, this.CVKorks.map(o => o[2])),
            'vlis' : vlis
        };
    }

    /**
     * 
     * @param {string} vuid 
     * @param {string} jwt 
     * @param {bigint[]} vlis 
     * @param {bigint} timestamp2 
     * @param {Point} gRMul 
     * @param {Point} gCVKR 
     * @param {bigint} S
     * @param {Uint8Array[]} ECDHi
     * @param {Point} gBlindH
     * @param {string} mode
     * @param {string} modelToSign
     * @param {Point} gR2
     * @param {boolean} test
     */
    async SignInCVK(vuid, jwt, vlis, timestamp2, gRMul, gCVKR, S, ECDHi, gBlindH, mode="default", modelToSign=null, gR2=null, test=false){
        const cvkClients = this.CVKorks.map(ork => new NodeClient(ork[1]))

        const pre_encSigs = cvkClients.map((client, i) => client.SignInCVK(vuid, jwt, timestamp2, gRMul, S, gCVKR, vlis[i], gBlindH, mode, modelToSign, gR2, test));
        const encSigs = await Promise.all(pre_encSigs);

        return await SignInCVKReply(encSigs, gCVKR, jwt, ECDHi, vlis);
    }
}