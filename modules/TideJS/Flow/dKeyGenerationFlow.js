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
import { GenShardReply, SendShardReply } from "../Math/KeyGeneration.js";
import OrkInfo from "../Models/OrkInfo.js";

export default class dKeyGenerationFlow {
    /**
     * @param {OrkInfo[]} orks 
     */
    constructor(orks) {
        /**
         * @type {OrkInfo[]}  // everything about orks of this user - orkID, orkURL, orkPublic
         */
        this.orks = orks;
    }

    /**
     * @param {string} uid 
     * @param {number} numKeys 
     * @param {Point[]} gMultipliers 
     */
    async GenShard(uid, numKeys, gMultipliers) {
        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const ids = this.orks.map(ork => BigInt(ork.orkID));
        const pre_GenShardResponses = clients.map(client => client.GenShard(uid, ids, numKeys, gMultipliers));
        const GenShardResponses = await Promise.all(pre_GenShardResponses);

        return GenShardReply(GenShardResponses);
    }

    /**
     * 
     * @param {string} uid 
     * @param {string[]} decryptedChallenges 
     * @param {Point} gMultiplier
     * @returns 
     */
    async UpdateShard(uid, decryptedChallenges, gMultiplier){
        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const ids = this.orks.map(ork => BigInt(ork.orkID));
        const pre_GenShardResponses = clients.map((client, i) => client.UpdateShard(uid, ids, decryptedChallenges[i], gMultiplier));
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
        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const pre_SendShardResponses = clients.map((client, i) => client.SendShard(uid, YijCipher[i], R2, auth, keyType))
        const SendShardResponses = await Promise.all(pre_SendShardResponses);

        return SendShardReply(uid, SendShardResponses, this.orks.map(ork => ork.orkPublic), timestamp, R2, gK1);
    }

    /**
     * @param {string} uid
     * @param {bigint} S 
     * @param {Point} auth
     * @param {string} keyType
     */
    async Commit(uid, S, keyType) {
        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const pre_CommitResponses = clients.map(client => client.Commit(uid, S, keyType));
        await Promise.all(pre_CommitResponses);
    }
}