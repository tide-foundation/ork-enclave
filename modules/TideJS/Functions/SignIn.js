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
import PrismFlow from "../Flow/Prism.js"
import { SHA256_Digest } from "../Tools/Hash.js"
import { BigIntToByteArray, Bytes2Hex, RandomBigInt, bytesToBase64, getCSharpTime } from "../Tools/Utils.js"
import SimulatorClient from "../Clients/SimulatorClient.js"
import NodeClient from "../Clients/NodeClient.js"
import { decryptData } from "../Tools/AES.js"
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow.js"
import HashToPoint from "../Tools/H2P.js"

export default class SignIn {
    /**
     * Config should include key/value pairs of: 
     * @example
     * {
     *  simulatorUrl: string
     * }
     * @example
     * @param {object} config 
     */
    constructor(config) {
        if (!Object.hasOwn(config, 'simulatorUrl')) { throw Error("Simulator Url has not been included in config") }

        /**
         * @type {string}
         */
        this.simulatorUrl = config.simulatorUrl
    }

    /**
     * Authenticates a user to the ORKs and decrypts their encrypted secret held by vendor.
     * @param {string} username 
     * @param {string} password 
     * @param {string} gVVK The vendor's public key
     */
    async start(username, password, gVVK) {
        const startTime = BigInt(Math.floor(Date.now() / 1000));
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        // Putting this up here to speed things up using await
        const simClient = new SimulatorClient(this.simulatorUrl);
        const pre_orkInfo = simClient.GetUserORKs(uid);
        const pre_cmkPub = simClient.GetKeyPublic(uid);

        const gUser = await HashToPoint(username.toLowerCase() + gVVK);
        const gBlurUser = gUser.times(r2);
        //convert password to point
        const gPass = await HashToPoint(password);
        const gBlurPass = gPass.times(r1);

        // get ork urls
        const cmkOrkInfo = await pre_orkInfo;
        const cmkPub = await pre_cmkPub;

        const authFlow = new dKeyAuthenticationFlow(cmkOrkInfo);
        const convertData = await authFlow.Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, cmkPub, gVVK);
        
        const vOrks = await simClient.GetUserORKs(convertData.VUID);
        authFlow.CVKorks = vOrks;
        const authData = await authFlow.Authenticate_and_PreSignInCVK(uid, convertData.VUID, convertData.decChallengei, convertData.encAuthRequests, convertData.gSessKeyPub, convertData.data_for_PreSignInCVK);

        const jwt = await authFlow.SignInCVK(convertData.VUID, convertData.jwt, authData.vlis, convertData.timestamp2, convertData.data_for_PreSignInCVK.gRMul, authData.gCVKR, authData.S, authData.ECDHi, authData.gBlindH);
        return jwt;
    }
}
