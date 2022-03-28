import { BigNumberish } from "starknet/dist/utils/number";
import { starknet } from "hardhat";
import { KeyPair, number, ec , hash, Signature} from "starknet";
import { getSelectorFromName } from "starknet/dist/utils/hash";
import MultiSignature from "./MultiSignature";
// import { pedersen, ec, sign } from "@toruslabs/starkware-crypto";

export default class Transaction {
    signatures: MultiSignature = new MultiSignature();
    body: any


    constructor(to: string, selector: string, calldata: any[], nonce: number, signers: any[]) {
        this.build(to, selector, calldata, nonce, signers);
    }   

    static buildFrom(to: string, selector: string, calldata: any[], nonce: number, signers: any[]): Transaction {
        return new Transaction(to, selector, calldata, nonce, signers);
    }

    private build(to: string, selector: string, calldata: any[], nonce: number, signers: any[]): any {
        const selectorFelt = getSelectorFromName(selector);
        const calls = [
            {
                contractAddress: to,
                entrypoint: selector,
                calldata: calldata,
            },
        ];

        const messageHash = hash.hashMulticall(to.toString(), calls, nonce.toString(), '0'); 

        let signatures: MultiSignature = new MultiSignature();
       

        if (signers.length == 1) {
            signatures.addSignature(signers[0].signToFelt(messageHash));
        } else {

            signers.forEach((e) => { 
                const sig1 = e.sign(messageHash);
                signatures.addSignature(sig1, e.publicKeyFelt); 
            })
        }

        this.signatures = signatures;

        this.body  = {
            call_array: [{to: BigInt(to),
                selector: BigInt(selectorFelt),
                data_offset: 0,
                data_len: calldata.length}],  
            calldata: calldata,
            nonce: nonce
        }
    }

    getSignatures(): MultiSignature {
        return this.signatures;
    }


    getFeltSignatures(): any[] {
        return this.signatures.getFeltSignatures();
    }

}