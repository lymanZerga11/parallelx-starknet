import { BigNumberish } from "starknet/dist/utils/number";
import { KeyPair, number, ec , hash, Signature} from "starknet";
import { BigNumber } from "ethers";
import { TWO } from "starknet/dist/constants";
import secp256k1, { Point } from "@noble/secp256k1";
import * as utils from "ethereumjs-util"


export default class SecpSignature {
    publicKey: Point;
    r: BigNumber;
    s: BigNumber;
    v?: BigNumber;

    static TWO = BigNumber.from(2);

    static SECP_P = this.TWO.pow(256).sub(this.TWO.pow(32)).sub(this.TWO.pow(9)).sub(this.TWO.pow(8)).sub(this.TWO.pow(7)).sub(this.TWO.pow(6)).sub(this.TWO.pow(4)).sub(1);

    static DEFAULT_PRIME = this.TWO.pow(251).add(BigNumber.from(17).mul(this.TWO.pow(192))).add(1)
    static BASE = this.TWO.pow(86);

    constructor(pk: Point, r: any, s: any, v: any = 0) {   
        this.publicKey = pk;
        this.r = BigNumber.from(r); 
        this.s = BigNumber.from(s);
        this.v = BigNumber.from(v);
        
    };


    toFeltSignature(): any {

        let signature: BigInt[] = [];

        signature.push(this.r.toBigInt(), this.s.toBigInt())

        return signature;
    }

    

    static packInt(number: BigNumber[]): BigNumber {
        var sum = BigNumber.from(0);

        for (let index = 0; index < number.length; index++) {
            sum = sum.add(this.asInt(number[index]).mul(this.TWO.pow(86 * (index))));
        }

        return sum;
    }

    static splitInt(number: BigNumber, parts: number = 3): BigNumber[] {
        
        let a: BigNumber[] = []
        for (let index = 0; index < parts; index++) {
            let num = number.div(this.BASE);
            a.push(number.mod(this.BASE));
            number = num;
        }
        
        return a;
    }

    static asInt(number: BigNumber): BigNumber {

        if (number.lt(this.SECP_P.div(2))) {
            return number;
        } else {
            return  number.sub(this.SECP_P);
        }        
    }

}