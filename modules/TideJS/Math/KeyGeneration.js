import Point from "../Ed25519/point.js";
import GenShardResponse from "../Models/GenShardResponse.js";
import SendShardResponse from "../Models/SendShardResponse.js";
import { createAESKey, decryptData, encryptData } from "../Tools/AES.js";
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js";
import { BigIntFromByteArray, BigIntToByteArray, bytesToBase64, ConcatUint8Arrays, median, mod, StringToUint8Array } from "../Tools/Utils.js";
import { GetLi } from "./SecretShare.js";

/**
 * @param {GenShardResponse[]} genShardResponses 
 */
export function GenShardReply(genShardResponses){
    const sortedShares = SortShares(genShardResponses.map(resp => resp.YijCiphers)); // sort shares so they can easily be sent to respective orks
    const timestamp = median(genShardResponses.map(resp => resp.Timestampi));
    const R2 = genShardResponses.reduce((sum, next) => next.GRi.add(sum), Point.infinity);

    // Interpolate the gMultipliers
    const gMultiplied = genShardResponses[0].GMultiplied.map((m, i) => m == null ? null : genShardResponses.reduce((sum, next) => sum.add(next.GMultiplied[i]), Point.infinity));

    // Interpolate the public
    const gK1 = genShardResponses.reduce((sum, next) => sum.add(next.GK1i), Point.infinity);

    return {sortedShares: sortedShares, timestamp: timestamp, R2: R2, gMultiplied: gMultiplied, gK1: gK1};
}

/**
 * @param {string} keyId
 * @param {SendShardResponse[]} sendShardResponses
 * @param {Point[]} mgORKi 
 * @param {bigint} timestamp
 * @param {Point} R2
 * @param {Point} gK1
 */
export async function SendShardReply(keyId, sendShardResponses, mgORKi, timestamp, R2, gK1){

    // Aggregate the signature
    const S = mod(sendShardResponses.reduce((sum, next) =>  next.Si + sum, BigInt(0)));

    // Generate EdDSA R from all the ORKs publics
    const M_data_to_hash = ConcatUint8Arrays([gK1.compress(), StringToUint8Array(timestamp.toString()), StringToUint8Array(keyId)]);
    const M = await SHA256_Digest(M_data_to_hash);
    const R = mgORKi.reduce((sum, next) => sum.add(next)).add(R2);

    // Prepare the signature message
    const H_data_to_hash = ConcatUint8Arrays([R.compress(), gK1.compress(), M]);
    const H = mod(BigIntFromByteArray(await SHA512_Digest(H_data_to_hash)), Point.order);

    // Verify signature validates
    if(!(Point.g.times(S).isEqual(R.add(gK1.times(H))))) throw new Error("SendShard: Signature test failed");

    return {S: S};
}

/**
 * @param {string[][]} sharesEncrypted 
 * @returns {string[][]}
 */
function SortShares(sharesEncrypted) {
    // Will sort array so that:
    // - Each ork receives a list of shares meant for them
    // - The shares are in the order which they were sent
    // To do this, I had to grab the first share of the first response, then the first share of the second response etc. and put it into a list
    // Then I had to grab the second share of the first response, then the second share of the second response etc. and put it into a list
    // The put those lists together, so we have an array of GenShardShare arrays
    // This was all done in the below line of code. Remember we rely on the order the shares are sent back
    return sharesEncrypted.map((_, i) => sharesEncrypted.map(share => share[i]))
}