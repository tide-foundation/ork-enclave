import NodeClient from "../Clients/NodeClient.js";
import { GetLi } from "../Math/SecretShare.js";
import Point from "../Ed25519/point.js";
import PrismConvertResponse from "../Models/PrismConvertResponse.js"
import { PrismConvertReply } from "../Math/KeyAuthentication.js";
import dKeyGenerationFlow from "./dKeyGenerationFlow.js";

export default class dChangePassFlow{
    /**
     * 
     * @param {[string, string, Point][]} cmkOrkInfo // everything about CMK orks of this user - orkID, orkURL, orkPublic 
     */
    constructor(cmkOrkInfo){
        this.cmkOrkInfo = cmkOrkInfo;
    }
    async GetPrism(uid, gBlurPass, r1, startTime){
        const clients = this.cmkOrkInfo.map(ork => new NodeClient(ork[1])) // create node clients

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map(client => client.PrismConvert(uid, gBlurPass, false));
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
        const ids = this.CMKorks.map(ork => BigInt(ork[0])); // create lis for all orks that responded
        const lis = ids.map(id => GetLi(id, ids, Point.order));

        /**@type {PrismConvertResponse[]} */
        // @ts-ignore
        const PrismConvertResponses = settledPromises.filter(promise => promise.status === "fulfilled").map(promise => promise.value); // .value will exist here as we have filtered the responses above
        
        return await PrismConvertReply(PrismConvertResponses, lis, this.cmkOrkInfo.map(c => c[2]), r1, startTime);
    }
    async ChangePrism(uid, gBlurNewPass){
        const prismGenFlow = new dKeyGenerationFlow(this.cmkOrkInfo);
        const prismGenShardData = await prismGenFlow.GenShard(uid, 1, [gBlurNewPass]);  // GenShard

        const gPassPRISM = prismGenShardData.gMultiplied[0].times(mod_inv(r[1]));
        const gPRISMAuth = Point.g.times(BigIntFromByteArray(await SHA256_Digest(gPassPRISM.toArray())));

        const prismSendShardData = await prismGenFlow.SendShard(uid, prismGenShardData.sortedShares, prismGenShardData.R2, prismGenShardData.timestamp, gPRISMAuth, "Prism", prismGenShardData.gK1);  // async SendShard
    }
    async Test(){

    }
    async CommitPrism(){

    }
}