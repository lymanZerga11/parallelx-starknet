import { BigNumberish } from "starknet/dist/utils/number";
import { starknet } from "hardhat";
import { KeyPair, number, ec , hash, Signature} from "starknet";
// import { pedersen, ec, sign } from "@toruslabs/starkware-crypto";

export default class MultiSignature {
    signatures: Signature = [];


    addSignature(signature: Signature, publikKey: any = undefined): void {
        if (publikKey)
            this.signatures.push(...signature, publikKey);
        else
            this.signatures.push(...signature);
    }


    getSignatures(): Signature {
        return this.signatures;
    }


    getFeltSignatures(): any[] {
        return this.signatures.map(e => BigInt(e.toString()));
    }

}