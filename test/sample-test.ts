import  { expect } from "chai";

import { starknet } from "hardhat";

import {number, hash} from "starknet";

import { pedersen, ec} from "@toruslabs/starkware-crypto";

import Signer from "./utils/signer"
import { formatSignature } from "starknet/dist/utils/stark";
import MultiSignature from "./utils/MultiSignature";

describe("Account Test", function () {
  this.timeout(300_000); // 5 min - recommended if used with Alpha testnet


  it("should handle signing transactions using the starkware-crypto library", async function() {

    const contractFactory = await starknet.getContractFactory("AccountImplementationV1");

    const privateKey = BigInt("1628448741648245036800002906075225705100596136133912895015035902954123957052");

    const ADD_OWNER_FUNCTION_SELECTOR = "0x12013618c68280aa51fbebbd715398b57f344251a3513ac215c4eac7a50d4be";

    // declare signers
    const signer = new Signer(privateKey);
    const signer1 = new Signer();
    const signer2 = new Signer();


    const contract = await contractFactory.deploy({_public_key: signer.publicKeyFelt});
  
    console.log("Deployed Account Contract at", contract.address);

    const messageHash = hash.hashMessage(contract.address, contract.address, ADD_OWNER_FUNCTION_SELECTOR, [signer1.publicKeyHex], '0');
    
    const signature = signer.signToFelt(messageHash);

    // invoke add owner to add signer1 as an owner
    const message_hash = await contract.invoke("execute", {
      to: BigInt(contract.address),
      selector: BigInt(ADD_OWNER_FUNCTION_SELECTOR),
      calldata: [signer1.publicKeyFelt],
      nonce: 0
    }, signature);




    const messageHash1 = hash.hashMessage(contract.address, contract.address, ADD_OWNER_FUNCTION_SELECTOR, [signer2.publicKeyHex], '1');
    console.log(number.hexToDecimalString(messageHash))
    
 
    const sig1 = signer.sign(messageHash1);
    const sig2 = signer1.sign(messageHash1);

    // init multisig isntance
    let multiSig = new MultiSignature();

    multiSig.addSignature(sig1, signer.publicKeyFelt);
    multiSig.addSignature(sig2, signer1.publicKeyFelt);
    
 
    
    // invoke add owner with a multisignature
     await contract.invoke("execute", {
      to: BigInt(contract.address),
      selector: BigInt(ADD_OWNER_FUNCTION_SELECTOR),
      calldata: [signer2.publicKeyHex],
      nonce: 1
    }, multiSig.getFeltSignatures());


  });



});
