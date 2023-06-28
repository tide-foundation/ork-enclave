import Point from "../Ed25519/point.js";
import { BigIntFromByteArray, base64ToBytes } from "../Tools/Utils.js";

export default class SendShardResponse{
    /**
     * @param {bigint} Si 
     */
    constructor(Si){
        this.Si = Si
    }

    static from(data){
        const obj = JSON.parse(data);
        const si = BigIntFromByteArray(base64ToBytes(obj.Si));
        return new SendShardResponse(si);
    }
}