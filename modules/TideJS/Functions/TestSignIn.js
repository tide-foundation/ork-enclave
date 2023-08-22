import TideJWT from "../ModelsToSign/TideJWT.js";
import { RandomBigInt } from "../Tools/Utils.js";
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow.js";
import Point from "../Ed25519/point.js";


export default class TestSignIn{
    constructor(cmkOrkInfo, cvkOrkInfo, newUser){
        this.cmkOrkInfo = cmkOrkInfo
        this.cvkOrkInfo = cvkOrkInfo // will change in future when vendor wants specific orks in new cvk rego
        this.cmkCommitted = newUser ? false : true;
    }

    /**
     * @param {string} uid
     * @param {Point} gUser 
     * @param {Point} gPass 
     * @param {string} gVVK 
     * @param {Point} cmkPub 
     * @param {Point} cvkPub 
     * @param {string} modelToSign
     * @returns 
     */
    async start(uid, gUser, gPass, gVVK, cmkPub, cvkPub, modelToSign_p=null){
        const modelRequested = (this.modelToSign == null && modelToSign_p == null) ? false : true;
        const modelToSign = this.modelToSign == null ? modelToSign_p : this.modelToSign; // figure out which one is the not null, if both are null, it will still be null

        const startTime = BigInt(Math.floor(Date.now() / 1000));
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();

        const gBlurUser = gUser.times(r2);
        
        const gBlurPass = gPass.times(r1);

        const authFlow = new dKeyAuthenticationFlow(this.cmkOrkInfo, this.cmkCommitted, false);
        const convertData = await authFlow.Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, cmkPub, gVVK);
        
        authFlow.CVKorks = this.cvkOrkInfo;
        const authData = await authFlow.Authenticate_and_PreSignInCVK(uid, convertData.VUID, convertData.decChallengei, convertData.encAuthRequests, convertData.gSessKeyPub, convertData.data_for_PreSignInCVK, modelRequested);

        const resp = await authFlow.SignInCVK(convertData.VUID, convertData.jwt, authData.vlis, convertData.timestamp2, convertData.data_for_PreSignInCVK.gRMul, authData.gCVKR, authData.S, authData.ECDHi, authData.gBlindH, this.mode, modelToSign, authData.model_gR);
        if(!(await TideJWT.verify(resp.jwt, cvkPub))) throw Error("Test sign in failed");
        return resp;
    }
}


