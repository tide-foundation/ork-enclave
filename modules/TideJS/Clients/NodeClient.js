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
import GenShardResponse from "../Models/GenShardResponse.js";
import ClientBase from "./ClientBase.js"
import SendShardResponse from "../Models/SendShardResponse.js";
import ConvertResponse from "../Models/ConvertResponse.js";

export default class NodeClient extends ClientBase {
    /**
     * @param {string} url
     */
    constructor(url) {
        super(url)
    }

    /**
     * @param {Point} gBlurUser
     * @param {Point} gBlurPass
     * @param {string} uid 
     * @param {Point} testPrismAuth
     * @returns {Promise<ConvertResponse>}
     */
    async Convert(uid, gBlurUser, gBlurPass, testPrismAuth=null) {
        const data = this._createFormData({ 
            'gBlurUser': gBlurUser.toBase64(), 
            'gBlurPass': gBlurPass.toBase64(),
            'testPrismAuth': testPrismAuth == null ? '' : testPrismAuth.toBase64()
        })
        const response = await this._post(`/CMK/Convert?uid=${uid}`, data)
        const responseData = await this._handleError(response, "Convert CMK/Prism");
        return ConvertResponse.from(responseData);
    }

    /**
     * @param {string} decryptedChallenge
     * @param {string} encryptedAuthRequest
     * @param {string} uid 
     * @param {Point} testPrismAuth
     * @returns {Promise<string>}
     */
    async Authenticate(uid, decryptedChallenge, encryptedAuthRequest, testPrismAuth=null) {
        const data = this._createFormData({ 
            'decryptedChallenge': decryptedChallenge, 
            'encAuthRequest': encryptedAuthRequest,
            'testPrismAuth': testPrismAuth == null ? '' : testPrismAuth.toBase64()
        })
        const response = await this._post(`/CMK/Authenticate?uid=${uid}`, data)

        const encSig = await this._handleError(response, "Authenticate");
        return encSig;
    }

    /**
     * 
     * @param {string} vuid 
     * @param {Point} gSessKeyPub 
     */
    async PreSignInCVK(vuid, gSessKeyPub){
        const data = this._createFormData({ 'gSessKeyPub': gSessKeyPub.toBase64() })
        const response = await this._post(`/CVK/PreSignIn?uid=${vuid}`, data)

        const encCVKR = await this._handleError(response, "PreSignInCVK");
        return encCVKR;
    }

    /**
     * 
     * @param {string} vuid 
     * @param {string} jwt 
     * @param {bigint} timestamp2 
     * @param {Point} gRMul 
     * @param {bigint} S 
     * @param {Point} gCVKR 
     * @param {bigint} li 
     * @param {Point} gBlindH
     * @param {boolean} uncommitted
     */
    async SignInCVK(vuid, jwt, timestamp2, gRMul, S, gCVKR, li, gBlindH, uncommitted=false){
        const data = this._createFormData({ 
            'jwt': jwt, 
            'timestamp2': timestamp2.toString(), 
            'gRMul': gRMul.toBase64(), 
            's': S.toString(), 
            'gCVKR': gCVKR.toBase64(),
            'li': li.toString(),
            'gBlindH': gBlindH.toBase64(),
            'uncommitted': uncommitted
        });
        const response = await this._post(`/CVK/SignIn?uid=${vuid}`, data)
        const encCVKSign = await this._handleError(response, "SignInCVK");
        return encCVKSign;
    }

    /**
     * @param {string} uid
     * @param {bigint[]} mIdORKij
     * @param {number} numKeys
     * @param {Point[]} gMultipliers
     * @returns {Promise<GenShardResponse>}
     */
    async GenShard(uid, mIdORKij, numKeys, gMultipliers) {
        const data = this._createFormData(
            {
                'mIdORKij': mIdORKij.map(n => n.toString()),
                'numKeys': numKeys,
                'gMultipliers': gMultipliers.map(p => p == null ? "" : p.toBase64()),
            }
        );
        const response = await this._post(`/Create/GenShard?uid=${uid}`, data);

        const responseData = await this._handleError(response, "GenShard");
        return GenShardResponse.from(responseData);
    }

    /**
     * @param {string} uid 
     * @param {string[]} shares 
     * @param {Point} R2
     * @param {Point} auth
     */
    async SendShard(uid, shares, R2, auth) {
        const data = this._createFormData(
            { 
                'yijCipher': shares, 
                'R2': R2.toBase64(),
                'auth': auth == null ? '' : auth.toBase64()
            });
        const response = await this._post(`/Create/SendShard?uid=${uid}`, data);

        const responseData = await this._handleError(response, "SendShard");
        return SendShardResponse.from(responseData);
    }


    /**
     * @param {string} uid 
     * @param {bigint} S  
     * @param {Point} auth
     */
    async Commit(uid, S, auth) {
        const data = this._createFormData(
            {
                'S': S.toString(),
                'auth': auth == null ? '' : auth.toBase64()
            }
        );
        const response = await this._post(`/Create/Commit?uid=${uid}`, data);
        const responseData = await this._handleError(response, "Commit");
        if(responseData !== "Account Created") Promise.reject("Commit: Accound creation failed");
    }
}