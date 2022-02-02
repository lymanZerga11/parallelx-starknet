import { BigNumberish } from "starknet/dist/utils/number";
import { starknet } from "hardhat";
import { KeyPair, number, ec , hash, Signature} from "starknet";
// import { pedersen, ec, sign } from "@toruslabs/starkware-crypto";

export default class Signer {
    publicKeyHex: string;
    publicKeyFelt: BigNumberish;
    keyPair: KeyPair;

    constructor(privateKey?: any) {    
        this.keyPair =  !!privateKey ? ec.getKeyPair(privateKey): ec.genKeyPair();

        this.publicKeyHex = ec.getStarkKey(this.keyPair);
        this.publicKeyFelt = number.toBN(this.publicKeyHex);
    };

    sign(msgHash: string): Signature {
        return ec.sign(this.keyPair, msgHash);
    }

    signToFelt(msgHash: string): any[] {
        return ec.sign(this.keyPair, msgHash).map(e => BigInt(e.toString()));
    }

}