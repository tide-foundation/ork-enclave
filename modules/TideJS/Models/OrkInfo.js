import Point from "../Ed25519/point";

export default class OrkInfo{
    /**
     * 
     * @param {string} orkID 
     * @param {Point} orkPublic 
     * @param {string} orkURL 
     */
    constructor(orkID, orkPublic, orkURL){
        this.orkID = orkID
        this.orkPublic = orkPublic
        this.orkURL = orkURL
    }

    static from(data){
        const json = JSON.parse(data);
        const pub = Point.fromB64(json.orkPublic);
        return new OrkInfo(json.orkID, pub, json.orkURL);
    }
}