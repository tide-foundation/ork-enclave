import TideJWT from "../ModelsToSign/TideJWT.js";
import { RandomBigInt } from "../Tools/Utils.js";
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow.js";
import Point from "../Ed25519/point.js";
import SimulatorClient from "../Clients/SimulatorClient.js";


export default class TestSignIn{
    constructor(cmkOrkInfo, cvkOrkInfo, cmkCommitted, cvkCommitted, prismCommitted){
        this.cmkOrkInfo = cmkOrkInfo
        this.cvkOrkInfo = cvkOrkInfo // will change in future when vendor wants specific orks in new cvk rego
        this.cmkCommitted = cmkCommitted
        this.cvkCommitted = cvkCommitted
        this.prismCommitted = prismCommitted

        this.savedState = undefined;
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
    async start(uid, gUser, gPass, gVVK, cmkPub, cvkPub=null){
        const startTime = BigInt(Math.floor(Date.now() / 1000));
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();

        const gBlurUser = gUser.times(r2);
        
        const gBlurPass = gPass.times(r1);

        const authFlow = new dKeyAuthenticationFlow(this.cmkOrkInfo, this.cmkCommitted, this.cvkCommitted, this.prismCommitted);
        const convertData = await authFlow.Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, cmkPub, gVVK);

        const gCVK = cvkPub == null ? await new SimulatorClient().GetKeyPublic(convertData.VUID) : cvkPub;

        this.savedState = {
            uid: uid,
            convertData: convertData,
            gCVK: gCVK,
            authFlow: authFlow
        }

        return {
            ok: true,
            dataType: "userData",
            newAccount: !this.cvkCommitted, // if cvk is NOT committed, it IS a new account
            publicKey: gCVK.toBase64(),
            uid: convertData.VUID
        };
    }

    async continue(mode="default", modelToSign=null){
        if(this.savedState == undefined) throw Error("No saved state");

        this.savedState.authFlow.CVKorks = this.cvkOrkInfo == undefined ? await new SimulatorClient().GetUserORKs(this.savedState.convertData.VUID) : this.cvkOrkInfo;
        const authData = await this.savedState.authFlow.Authenticate_and_PreSignInCVK(this.savedState.uid, this.savedState.convertData.VUID, this.savedState.convertData.decChallengei, 
            this.savedState.convertData.encAuthRequests, this.savedState.convertData.gSessKeyPub, this.savedState.convertData.data_for_PreSignInCVK, (modelToSign != null));

        const resp = await this.savedState.authFlow.SignInCVK(this.savedState.convertData.VUID, this.savedState.convertData.jwt, authData.vlis, this.savedState.convertData.timestamp2, 
            this.savedState.convertData.data_for_PreSignInCVK.gRMul, authData.gCVKR, authData.S, authData.ECDHi, authData.gBlindH, mode, modelToSign, authData.model_gR);
        if(!(await TideJWT.verify(resp.jwt, this.savedState.gCVK))) throw Error("Test sign in failed");
        return {
            ok: true,
            dataType: "completed",
            TideJWT: resp.jwt, 
            modelSig: resp.modelSig
        };
    }
}


