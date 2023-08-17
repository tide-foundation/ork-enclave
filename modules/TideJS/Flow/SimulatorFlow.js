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
import SimulatorClient from "../Clients/SimulatorClient.js";

export default class SimulatorFlow{
     
    static async GetActiveOrks(){
        const allOrks = await new SimulatorClient().GetAllORKs(); // get all registered orks' urls
        const promises = allOrks.map(ork => new NodeClient(ork.url).isActive());

        const settled = await Promise.allSettled(promises);
        var activeOrks = [];
        settled.forEach((promise, i) => {
            if(promise.status === "fulfilled") activeOrks.push(allOrks[i]) // create new ork list on orks which replied
        }); 

        return activeOrks;
    }
}