import Point from "../Ed25519/point";
import { SHA256_Digest } from "./Hash";
import { ConcatUint8Arrays, RandomBigInt, XOR, bytesToBase64 } from "./Utils";

/**
 * 
 * @param {Uint8Array} secretData 
 * @param {Point} publicKey 
 */
export async function encrypt_ElGamal(secretData, publicKey){
    if(secretData.length !== 32) throw Error("ElGamal: Secret data must be 32 bytes");
    
    const r = RandomBigInt();
    const c1 = Point.g.times(r).toArray();
    const key = await SHA256_Digest(publicKey.times(r).toArray());
    const c2 = XOR(secretData, key);

    const encryptedData = bytesToBase64(ConcatUint8Arrays([c1, c2]));
    return encryptedData;
}