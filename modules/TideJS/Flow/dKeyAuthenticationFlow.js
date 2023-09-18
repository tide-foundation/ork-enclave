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
import PrismConvertResponse from "../Models/PrismConvertResponse.js";
import OrkInfo from "../Models/OrkInfo.js";
import { PromiseRace } from "../Tools/Utils.js";

export default class dKeyAuthenticationFlow{
    /**
     * @param {OrkInfo[]} CMKorks 
     * @param {boolean} cmkCommitted
     * @param {boolean} cvkCommitted
     * @param {boolean} prismCommitted
     */
    constructor(CMKorks, cmkCommitted, cvkCommitted, prismCommitted) {
        /**
         * @type {OrkInfo[]}  // everything about CMK orks of this user - orkID, orkURL, orkPublic
         */
        this.CMKorks = CMKorks;
        /**
         * @type {OrkInfo[]}
         */
        this.CVKorks = CMKorks;
        this.threshold = 3;
        this.cmkCommitted = cmkCommitted
        this.cvkCommitted = cvkCommitted
        this.prismCommitted = prismCommitted
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
     */
    async Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, gCMK, gVVK){
        const clients = this.CMKorks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map((client, i) => client.Convert(i, uid, gBlurUser, gBlurPass, this.cmkCommitted, this.prismCommitted));
        const unsortedConvertResponses = await PromiseRace(pre_ConvertResponses, this.threshold, "CMK");

        /**@type {{index: number, CMKConvertResponse: string, PrismConvertResponse: PrismConvertResponse}[]} */
        const ConvertResponses = unsortedConvertResponses.sort((a, b) => a.index - b.index);
        //remove CMKOrks that are not at indexes in convert responses
        this.CMKorks = this.CMKorks.filter((_, i) => ConvertResponses.every(resp => resp.index != i)); // if ork at index 0 does not include a response with index 0, remove ork

        // Generate lis for CMKOrks based on the ones that replied
        const ids = this.CMKorks.map(ork => BigInt(ork.orkID)); // create lis for all orks that responded
        const lis = ids.map(id => GetLi(id, ids, Point.order));

        
        const {prismAuthis, deltaTime} = await PrismConvertReply(ConvertResponses.map(c => c.PrismConvertResponse), lis, this.CMKorks.map(c => c.orkPublic), r1, startTime);
        return await CmkConvertReply(uid, ConvertResponses.map(c => c.CMKConvertResponse), ConvertResponses.map(c => c.PrismConvertResponse.EncChallengei), lis, prismAuthis, gCMK, r2, deltaTime, gVVK);
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
     */
    async Authenticate_and_PreSignInCVK(uid, vuid, decryptedChallengei, encryptedAuthRequest, gSessKeyPub, data_for_PreSignInCVK, modelRequested=false){
        const cmkClients = this.CMKorks.map(ork => new NodeClient(ork.orkURL))
        // TODO: Once sim client ceases to exist, fill in this.CVKorks here by quering a cmkork
        const cvkClients = this.CVKorks.map(ork => new NodeClient(ork.orkURL))

        const pre_encSig = cmkClients.map((client, i) => client.Authenticate(uid, decryptedChallengei[i], encryptedAuthRequest[i], this.cmkCommitted, this.prismCommitted))
       // const pre_encGRData = cvkClients.map(client => client.PreSignInCVK(vuid, gSessKeyPub, modelRequested));

        const encSig = await Promise.all(pre_encSig);

        // Here we also find out which ORKs are up
        const pre_encGRData = cvkClients.map((client, i) => client.PreSignInCVK(i, vuid, gSessKeyPub, modelRequested));
        const unsorted_encGRData = await PromiseRace(pre_encGRData, this.threshold, "CVK");

        /**@type {{index: number, encGRData: string}[]} */
        const encGRData = unsorted_encGRData.sort((a, b) => a.index - b.index);
        //remove CMKOrks that are not at indexes in convert responses
        this.CVKorks = this.CVKorks.filter((_, i) => encGRData.every(resp => resp.index != i)); // if ork at index 0 does not include a response with index 0, remove ork

        // Generate lis for CVKOrks based on the ones that replied
        const vids = this.CVKorks.map(ork => BigInt(ork.orkID)); 
        const vlis = vids.map(id => GetLi(id, vids, Point.order));

        return {
            ... await PreSignInCVKReply(encSig, encGRData.map(a => a.encGRData), data_for_PreSignInCVK, this.CVKorks.map(o => o.orkPublic)),
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
     */
    async SignInCVK(vuid, jwt, vlis, timestamp2, gRMul, gCVKR, S, ECDHi, gBlindH, mode="default", modelToSign=null, gR2=null){
        const cvkClients = this.CVKorks.map(ork => new NodeClient(ork.orkURL))

        const pre_encSigs = cvkClients.map((client, i) => client.SignInCVK(vuid, jwt, timestamp2, gRMul, S, gCVKR, vlis[i], gBlindH, mode, modelToSign, gR2, this.cvkCommitted));
        const encSigs = await Promise.all(pre_encSigs);

        return await SignInCVKReply(encSigs, gCVKR, gR2, jwt, ECDHi, vlis);
    }
}