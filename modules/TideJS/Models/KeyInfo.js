import Point from "../Ed25519/point"
import OrkInfo from "./OrkInfo";

export default class KeyInfo{
    /**
     * 
     * @param {string} keyID 
     * @param {Point} keyPublic 
     * @param {OrkInfo[]} orkInfo 
     */
    constructor(keyID, keyPublic, orkInfo){
        this.keyID = keyID
        this.keyPublic = keyPublic
        this.orkInfo = orkInfo
    }

    static from(data){
        const json = JSON.parse(data);
        const pub = Point.fromB64(json.keyPublic);
        const orkInfo = json.orkInfos.map(orkInfo => OrkInfo.from(orkInfo));
        return new KeyInfo(json.keyID, pub, orkInfo);
    }
}