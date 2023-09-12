import SimulatorClient from "../Clients/SimulatorClient.js";
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow.js";
import HashToPoint from "../Tools/H2P.js";
import { RandomBigInt } from "../Tools/Utils.js";
import Point from "../Ed25519/point.js";
import dChangePassFlow from "../Flow/dChangePassFlow.js";
import { Bytes2Hex } from "../Tools/Utils.js";
import { SHA256_Digest } from "../Tools/Hash.js";

export default class ChangePassword{

    constructor(){
        this.savedState = undefined;
    }

    /**
     * @param {string} username 
     * @param {string} oldPassword 
     * @param {string} newPassword 
     * @param {string} gVVK
     */
    async start(username, oldPassword, newPassword, gVVK){
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        // Putting this up here to speed things up using await
        const simClient = new SimulatorClient();
        const pre_orkInfo = simClient.GetUserORKs(uid);
        const pre_cmkPub = simClient.GetKeyPublic(uid);

        //convert password to point
        const gUser = await HashToPoint(username.toLowerCase() + gVVK);
        const gPass = await HashToPoint(oldPassword);
        const gNewPass = await HashToPoint(newPassword);
        const gBlurPass = gPass.times(r1);
        const gBlurNewPass = gNewPass.times(r2);

        // get ork urls
        const cmkOrkInfo = await pre_orkInfo;
        const cmkPub = await pre_cmkPub;

        const changePassFlow = new dChangePassFlow(cmkOrkInfo);
        const decryptedChallenges = await changePassFlow.Authenticate(uid, gBlurPass, r1);
        await changePassFlow.ChangePrism(uid, gBlurNewPass, r2, decryptedChallenges);
        const resp = await changePassFlow.StartTest(uid, gUser, gNewPass, gVVK, cmkPub);

        this.savedState = {
            uid: uid,
            changePassFlow: changePassFlow
        }

        return resp;
    }

    async continue(mode="default", modelToSign=null){
        if(this.savedState == undefined) throw Error("No saved state exists");
        const resp = await this.savedState.changePassFlow.ConintueTest(mode, modelToSign);
        await this.savedState.changePassFlow.CommitPrism(this.savedState.uid);
        return resp;
    }
}