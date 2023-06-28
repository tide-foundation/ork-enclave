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
     * @param {Point[]} gMultipliers 
     */
    async GenShard(uid, numKeys, gMultipliers) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const ids = this.orks.map(ork => BigInt(ork[0]));
        const pre_GenShardResponses = clients.map(client => client.GenShard(uid, ids, numKeys, gMultipliers));
        const GenShardResponses = await Promise.all(pre_GenShardResponses);

        return GenShardReply(GenShardResponses);
    }

    /**
     * @param {string} uid 
     * @param {string[][]} YijCipher 
     * @param {Point} R2
     * @param {bigint} timestamp
     * @param {Point} auth
     * @param {string} keyType
     * @param {Point} gK1
     */
    async SendShard(uid, YijCipher, R2, timestamp, auth, keyType, gK1) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_SendShardResponses = clients.map((client, i) => client.SendShard(uid, YijCipher[i], R2, auth, keyType))
        const SendShardResponses = await Promise.all(pre_SendShardResponses);

        return SendShardReply(uid, SendShardResponses, this.orks.map(ork => ork[2]), timestamp, R2, gK1);
    }

    /**
     * @param {string} uid
     * @param {bigint} S 
     * @param {Point} auth
     * @param {string} keyType
     */
    async Commit(uid, S, keyType) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_CommitResponses = clients.map(client => client.Commit(uid, S, keyType));
        await Promise.all(pre_CommitResponses);
    }
}