import NodeClient from "../Clients/NodeClient.js";
import { GetLi } from "../Math/SecretShare.js";
import Point from "../Ed25519/point.js";
import PrismConvertResponse from "../Models/PrismConvertResponse.js"
import { GetDecryptedChallenge, PrismConvertReply } from "../Math/KeyAuthentication.js";
import dKeyGenerationFlow from "./dKeyGenerationFlow.js";
import { mod_inv, BigIntFromByteArray } from "../Tools/Utils.js";
import { SHA256_Digest } from "../Tools/Hash.js";
import TestSignIn from "../Functions/TestSignIn.js";

export default class dChangePassFlow{
    /**
     * 
     * @param {[string, string, Point][]} cmkOrkInfo // everything about CMK orks of this user - orkID, orkURL, orkPublic 
     */
    constructor(cmkOrkInfo){
        this.cmkOrkInfo = cmkOrkInfo;
        this.savedState = undefined;
    }
    async Authenticate(uid, gBlurPass, r1){
        const clients = this.cmkOrkInfo.map(ork => new NodeClient(ork[1])) // create node clients

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map(client => client.PrismConvert(uid, gBlurPass, true));
        const settledPromises = await Promise.allSettled(pre_ConvertResponses);// determine which promises were fulfilled
        var activeOrks = []
        settledPromises.forEach((promise, i) => {
            if(promise.status === "fulfilled") activeOrks.push(this.cmkOrkInfo[i]) // create new ork list on orks which replied
        }); 
        if(activeOrks.length < this.threshold){
            // @ts-ignore
            if(settledPromises.filter(promise => promise.status === "rejected").some(promise => promise.reason === "Too many attempts")) throw new Error("Too many attempts")
            else throw new Error("CMK Orks for this account are down");
        } 
        this.cmkOrkInfo = activeOrks;

        // Generate lis for CMKOrks based on the ones that replied
        const ids = this.cmkOrkInfo.map(ork => BigInt(ork[0])); // create lis for all orks that responded
        const lis = ids.map(id => GetLi(id, ids, Point.order));

        /**@type {PrismConvertResponse[]} */
        // @ts-ignore
        const PrismConvertResponses = settledPromises.filter(promise => promise.status === "fulfilled").map(promise => promise.value); // .value will exist here as we have filtered the responses above
        
        return await GetDecryptedChallenge(PrismConvertResponses, lis, this.cmkOrkInfo.map(c => c[2]), r1);
    }
    /**
     * @param {string} uid 
     * @param {Point} gBlurNewPass 
     * @param {bigint} r2 
     * @param {string[]} decryptedChallenges 
     * @returns 
     */
    async ChangePrism(uid, gBlurNewPass, r2, decryptedChallenges){
        const prismGenFlow = new dKeyGenerationFlow(this.cmkOrkInfo);
        const prismGenShardData = await prismGenFlow.UpdateShard(uid, decryptedChallenges, gBlurNewPass);  // GenShard

        const gNewPassPRISM = prismGenShardData.gMultiplied[0].times(mod_inv(r2));
        const gNewPRISMAuth = Point.g.times(BigIntFromByteArray(await SHA256_Digest(gNewPassPRISM.toArray())));

        const prismSendShardData = await prismGenFlow.SendShard(uid, prismGenShardData.sortedShares, prismGenShardData.R2, prismGenShardData.timestamp, gNewPRISMAuth, "Prism", prismGenShardData.gK1);  // async SendShard
        this.savedState = {
            prismSig: prismSendShardData.S,
            genFlow: prismGenFlow
        };
    }
    /**
     * @param {string} uid 
     * @param {Point} gUser 
     * @param {Point} gNewPass 
     * @param {string} gVVK 
     * @param {Point} cmkPub 
     * @param {Point} cvkPub 
     * @returns 
     */
    async Test(uid, gUser, gNewPass, gVVK, cmkPub, cvkPub=null){
        const testSignIn = new TestSignIn(this.cmkOrkInfo, undefined, true, true, false);
        const {jwt} = await testSignIn.start(uid, gUser, gNewPass, gVVK, cmkPub, cvkPub);
        return jwt;
    }
    async CommitPrism(uid){
        if(this.savedState == undefined) throw Error("No saved state")
        await this.savedState.genFlow.Commit(uid, this.savedState.prismSig, "Prism");
    }
}