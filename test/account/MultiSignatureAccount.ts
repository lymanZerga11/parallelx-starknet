import  { expect } from "chai";
import { starknet } from "hardhat";
import Signer from "../utils/signer"
import Transaction from "../utils/Transaction";


describe("MultiSignature Account Test", function () {

    this.timeout(3000000); // 50 minutes

    const signer1 = new Signer();
    const signer2 = new Signer();
    const signer3 = new Signer();

    let nonce: number = 0;


    const increaseNonce = () => { nonce++ };

    const deployMultiSigContract = async (public_keys: any[], threshold: number) => {
        const contractFactory = await starknet.getContractFactory("MultiSignatureAccount");

        let keys: any[] = [];

        public_keys.forEach((e) => keys.push(e.publicKeyFelt));

        const contract = await contractFactory.deploy({public_keys: keys, threshold: threshold});

        return contract;
    }


    it("should deploy MultiSig Contract with 1 public key", async function() {

        const contract = await deployMultiSigContract([signer1], 1);

        const threshold = await contract.call('get_threshold');

        expect(threshold.res).to.deep.equal(BigInt(1));

    });


    it("should deploy MultiSig Contract with 2 public keys with threshold 1", async function() {

        const contract = await deployMultiSigContract([signer1, signer2], 1);

        const threshold = await contract.call('get_threshold');

        expect(threshold.res).to.deep.equal(BigInt(1));


        const public_key_count = await contract.call('get_public_key_count');

        expect(public_key_count.res).to.deep.equal(BigInt(2));

    });

    it("should deploy MultiSig Contract with 2 public keys with threshold 2", async function() {

        const contract = await deployMultiSigContract([signer1, signer2], 2);

        const threshold = await contract.call('get_threshold');

        expect(threshold.res).to.deep.equal(BigInt(2));
    });


    it("should reject deploying MultiSig Contract with 2 public keys with threshold 3", async function() {

        expect(deployMultiSigContract([signer1, signer2], 3)).to.be.reverted; //should fail

    });

    it("should add new public key to a 1 owner wallet and increase threshold", async function() {

        const contract = await  deployMultiSigContract([signer1], 1);

        let tx = new Transaction(contract.address, 'add_public_key', [signer2.publicKeyFelt, 2], 0, [signer1]);
        const message_hash = await contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()});

        const threshold = await contract.call('get_threshold');
        expect(threshold.res).to.deep.equal(BigInt(2));

        const public_key_count = await contract.call('get_public_key_count');

        expect(public_key_count.res).to.deep.equal(BigInt(2));
    });

    it("should add new public key to a 2 owners wallet and increase threshold", async function() {

        const contract = await  deployMultiSigContract([signer1, signer2], 2);

        let tx = new Transaction(contract.address, 'add_public_key', [signer3.publicKeyFelt, 3], 0, [signer1, signer2]);

        const message_hash = await contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()});

        const threshold = await contract.call('get_threshold');
        expect(threshold.res).to.deep.equal(BigInt(3));


        const public_key_count = await contract.call('get_public_key_count');
        expect(public_key_count.res).to.deep.equal(BigInt(3));

    });


    it("should reject adding new public key to a 2 owners wallet when only one signature is provided", async function() {

        const contract = await  deployMultiSigContract([signer1, signer2], 2);

        let tx = new Transaction(contract.address, 'add_public_key', [signer3.publicKeyFelt, 3], 0, [signer1]);

        expect(contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()})).to.be.reverted;

        const threshold = await contract.call('get_threshold');
        expect(threshold.res).to.deep.equal(BigInt(2));

        const public_key_count = await contract.call('get_public_key_count');
        expect(public_key_count.res).to.deep.equal(BigInt(2));
    });


    it("should remove public key from a 2 owners wallet and decrease threshold", async function() {
        const contract = await  deployMultiSigContract([signer1, signer2], 2);

        let tx = new Transaction(contract.address, 'remove_public_key', [signer2.publicKeyFelt, 1, 0], 0, [signer1, signer2]);

        const message_hash = await contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()});

        const threshold = await contract.call('get_threshold');
        expect(threshold.res).to.deep.equal(BigInt(1));
    });



    it("should reject removing public key from a 2 owners wallet without decreasing threshold", async function() {
        const contract = await  deployMultiSigContract([signer1, signer2], 2);

        let tx = new Transaction(contract.address, 'remove_public_key', [signer2.publicKeyFelt, 2, 0], 0, [signer1, signer2]);

        expect(contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()})).to.be.reverted;

        const threshold = await contract.call('get_threshold');
        expect(threshold.res).to.deep.equal(BigInt(2));
    });


    it("should remove default public key when new default public key is provided", async function() {
        const contract = await  deployMultiSigContract([signer1, signer2], 2);

        let tx = new Transaction(contract.address, 'remove_public_key', [signer1.publicKeyFelt, 1, signer2.publicKeyFelt], 0, [signer1, signer2]);

        const message_hash = await contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()});

        const public_key = await contract.call('get_public_key');
        expect(public_key.res.toString()).to.deep.equal(signer2.publicKeyFelt.toString());
    });

    it("should reject removing default public key without providing new default public key", async function() {
        const contract = await  deployMultiSigContract([signer1, signer2], 2);

        let tx = new Transaction(contract.address, 'remove_public_key', [signer1.publicKeyFelt, 1, 0], 0, [signer1, signer2]);

        expect(contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()})).to.be.reverted;

        const threshold = await contract.call('get_threshold');
        expect(threshold.res).to.deep.equal(BigInt(2));
    });


    it("should decrease threshold from 2 to 1 in a 2 owners wallet", async function() {
        const contract = await  deployMultiSigContract([signer1, signer2], 2);

        let tx = new Transaction(contract.address, 'change_threshold', [1], 0, [signer1, signer2]);

        const message_hash = await contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()});

        const threshold = await contract.call('get_threshold');
        expect(threshold.res).to.deep.equal(BigInt(1));
    });


    it("should change default public key", async function() {
        const contract = await  deployMultiSigContract([signer1, signer2], 2);

        let tx = new Transaction(contract.address, 'change_default_public_key', [signer2.publicKeyFelt], 0, [signer1, signer2]);

        const message_hash = await contract.invoke("execute", tx.body, {signature: tx.getFeltSignatures()});

        const public_key = await contract.call('get_public_key');
        expect(public_key.res.toString()).to.deep.equal(signer2.publicKeyFelt.toString());
    });

});