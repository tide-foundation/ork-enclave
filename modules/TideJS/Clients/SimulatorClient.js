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

import Point from "../Ed25519/point.js"
import ClientBase from "./ClientBase.js"
import NodeClient from "./NodeClient.js";

// TODO: Remove this client. All API requests for blockchain stuff should go through ORKs
export default class SimulatorClient extends ClientBase {
    /**
     * @param {string} url
     */
    constructor(){
        super(window.location.origin)
    }

    /**
     * This method will query the simulator for all information about all ORKs and return
     * an array compromising of each ORK's name, url and public.
     */
    async GetAllORKs(){
        const response = await this._get('/simulator/orks');
        const responseData = await this._handleErrorSimulator(response);
        const formattedResponse = JSON.parse(responseData)
        const returnedResponse = formattedResponse.map(orkEntry => new {id: orkEntry.orkId, name: orkEntry.orkName, url: orkEntry.orkUrl, public: orkEntry.orkPub});
        return returnedResponse;
    }

    /**
     * 
     * @param {string} uid 
     * @returns {Promise<[string, string, Point][]>}
     */
    async GetUserORKs(uid){
        const response = await this._get(`/simulator/userorks?uid=${uid}`);
        const responseData = await this._handleErrorSimulator(response);
        const resp_obj = JSON.parse(responseData);
        const pubs = resp_obj.orkPubs.map(pub => Point.fromB64(pub));
        const returnData = pubs.map((pub, i) => [resp_obj.orkIds[i], resp_obj.orkUrls[i], pub]);  // format data so instead of ( [urls], [points] ) we have (url1, point1), (url2, point2) []
        return returnData
    }

    /**
     * 
     * @param {string} uid 
     * @returns {Promise<Point>}
     */
    async GetKeyPublic(uid){
        const response = await this._get(`/simulator/keyentry?uid=${uid}`);
        const responseData = await this._handleErrorSimulator(response);
        const resp_obj = JSON.parse(responseData);
        return Point.fromB64(resp_obj.public);
    }

}