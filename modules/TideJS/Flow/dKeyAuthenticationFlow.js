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
     * @param {Point} testGPrismAuth
     */
    async Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, gCMK, gVVK, testGPrismAuth=null){
        const clients = this.CMKorks.map(ork => new NodeClient(ork[1])) // create node clients

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map(client => client.Convert(uid, gBlurUser, gBlurPass, testGPrismAuth));
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
     * @param {Point} testPrismAuth
     */
    async Authenticate_and_PreSignInCVK(uid, vuid, decryptedChallengei, encryptedAuthRequest, gSessKeyPub, data_for_PreSignInCVK, testPrismAuth=null){
        const cmkClients = this.CMKorks.map(ork => new NodeClient(ork[1]))
        const cvkClients = this.CVKorks.map(ork => new NodeClient(ork[1]))

        const pre_encSig = cmkClients.map((client, i) => client.Authenticate(uid, decryptedChallengei[i], encryptedAuthRequest[i], testPrismAuth))
        const pre_encCVKRi = cvkClients.map(client => client.PreSignInCVK(vuid, gSessKeyPub));

        const encSig = await Promise.all(pre_encSig);

        // Determine which CVK orks responded
        const settledPromises = await Promise.allSettled(pre_encCVKRi);// determine which promises were fulfilled
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
        const encCVKR = settledPromises.filter(promise => promise.status === "fulfilled").map(promise => promise.value); // .value will exist here as we have filtered the responses above
      
        return {
            ... await PreSignInCVKReply(encSig, encCVKR, data_for_PreSignInCVK, this.CVKorks.map(o => o[2])),
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
     * @param {boolean} uncommitted
     */
    async SignInCVK(vuid, jwt, vlis, timestamp2, gRMul, gCVKR, S, ECDHi, uncommitted=false){
        const cvkClients = this.CVKorks.map(ork => new NodeClient(ork[1]))

        const pre_encCVKSig = cvkClients.map((client, i) => client.SignInCVK(vuid, jwt, timestamp2, gRMul, S, gCVKR, vlis[i], true));
        const encCVKSign = await Promise.all(pre_encCVKSig);

        return await SignInCVKReply(encCVKSign, gCVKR, jwt, ECDHi, vlis);
    }
}