import NodeClient from "../Clients/NodeClient.js";
import Point from "../Ed25519/point.js";
import { GenShardReply, SendShardReply } from "../Math/KeyGeneration.js";

export default class dKeyGenerationFlow {
    /**
     * @param {[string, string, Point][]} orks 
     */
    constructor(orks) {
        /**
         * @type {[string, string, Point][]}  // everything about orks of this user - orkID, orkURL, orkPublic
         */
        this.orks = orks;
    }

    /**
     * @param {string} uid 
     * @param {number} numKeys 
     */
    async GenShard(uid, numKeys) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const ids = this.orks.map(ork => BigInt(ork[0]));
        const pre_GenShardResponses = clients.map(client => client.GenShard(uid, ids, numKeys));
        const GenShardResponses = await Promise.all(pre_GenShardResponses);

        return GenShardReply(GenShardResponses);
    }

    /**
     * @param {string} uid 
     * @param {string[][]} YijCipher 
     * @param {Point} R2
     * @param {Point[]} gMultipliers
     * @param {bigint} timestamp
     * @param {Point} auth
     */
    async SendShard(uid, YijCipher, R2, gMultipliers, timestamp, auth=null) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_SendShardResponses = clients.map((client, i) => client.SendShard(uid, YijCipher[i], R2, gMultipliers, auth))
        const SendShardResponses = await Promise.all(pre_SendShardResponses);

        return SendShardReply(uid, SendShardResponses, this.orks.map(ork => ork[2]), timestamp, R2);
    }

    /**
     * @param {string} uid
     * @param {bigint} S 
     * @param {string[]} EncCommitStatei 
     * @param {Point} auth
     */
    async Commit(uid, S, EncCommitStatei, auth=null) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_CommitResponses = clients.map((client, i) => client.Commit(uid, S, EncCommitStatei[i], auth));
        await Promise.all(pre_CommitResponses);
    }
}