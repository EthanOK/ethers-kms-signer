"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AwsKmsSigner = void 0;
/* eslint-disable import/no-extraneous-dependencies */
const client_kms_1 = require("@aws-sdk/client-kms");
const asn1_ecc_1 = require("@peculiar/asn1-ecc");
const asn1_schema_1 = require("@peculiar/asn1-schema");
const asn1_x509_1 = require("@peculiar/asn1-x509");
const ethers_1 = require("ethers");
class AwsKmsSigner extends ethers_1.AbstractSigner {
    config;
    client;
    address;
    constructor(config, provider) {
        super(provider);
        this.config = config;
        this.client = this._createKMSClient(config.region, config.credentials);
    }
    connect(provider) {
        return new AwsKmsSigner(this.config, provider);
    }
    async getAddress() {
        if (!this.address) {
            const command = new client_kms_1.GetPublicKeyCommand({ KeyId: this.config.keyId });
            const response = await this.client.send(command);
            const publicKeyHex = response.PublicKey;
            if (!publicKeyHex) {
                throw new Error(`Could not get Public Key from KMS.`);
            }
            const ecPublicKey = asn1_schema_1.AsnConvert.parse(Buffer.from(publicKeyHex), asn1_x509_1.SubjectPublicKeyInfo).subjectPublicKey;
            // The public key starts with a 0x04 prefix that needs to be removed
            // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
            this.address = `0x${(0, ethers_1.keccak256)(new Uint8Array(ecPublicKey.slice(1, ecPublicKey.byteLength))).slice(-40)}`;
        }
        return this.address;
    }
    async signTransaction(tx) {
        // Replace any Addressable or ENS name with an address
        const { to, from } = await (0, ethers_1.resolveProperties)({
            to: tx.to ? (0, ethers_1.resolveAddress)(tx.to, this.provider) : undefined,
            from: tx.from ? (0, ethers_1.resolveAddress)(tx.from, this.provider) : undefined,
        });
        if (to != null) {
            tx.to = to;
        }
        if (from != null) {
            tx.from = from;
        }
        const address = await this.getAddress();
        if (tx.from != null) {
            (0, ethers_1.assertArgument)((0, ethers_1.getAddress)(tx.from) === address, "transaction from address mismatch", "tx.from", tx.from);
            delete tx.from;
        }
        // Build the transaction
        const btx = ethers_1.Transaction.from(tx);
        btx.signature = await this._sign(btx.unsignedHash);
        return btx.serialized;
    }
    async signMessage(message) {
        const signature = await this._sign((0, ethers_1.hashMessage)(message));
        return signature.serialized;
    }
    async sign(digest) {
        const signature = await this._sign(digest);
        return signature.serialized;
    }
    async signTypedData(domain, types, value) {
        // Populate any ENS names
        const populated = await ethers_1.TypedDataEncoder.resolveNames(domain, types, value, async (name) => {
            // @TODO: this should use resolveName; addresses don't
            //        need a provider
            (0, ethers_1.assert)(this.provider != null, "cannot resolve ENS names without a provider", "UNSUPPORTED_OPERATION", {
                operation: "resolveName",
                info: { name },
            });
            const address = await this.provider.resolveName(name);
            (0, ethers_1.assert)(address != null, "unconfigured ENS name", "UNCONFIGURED_NAME", {
                value: name,
            });
            return address;
        });
        const signature = await this._sign(ethers_1.TypedDataEncoder.hash(populated.domain, types, populated.value));
        return signature.serialized;
    }
    _createKMSClient(region, credentials) {
        return new client_kms_1.KMSClient({ region, credentials });
    }
    async _sign(digest) {
        (0, ethers_1.assertArgument)((0, ethers_1.dataLength)(digest) === 32, "invalid digest length", "digest", digest);
        const command = new client_kms_1.SignCommand({
            KeyId: this.config.keyId,
            Message: (0, ethers_1.getBytes)(digest),
            MessageType: "DIGEST",
            SigningAlgorithm: "ECDSA_SHA_256",
        });
        const response = await this.client.send(command);
        const signatureHex = response.Signature;
        if (!signatureHex) {
            throw new Error("Could not fetch Signature from KMS.");
        }
        const signature = asn1_schema_1.AsnConvert.parse(Buffer.from(signatureHex), asn1_ecc_1.ECDSASigValue);
        let s = (0, ethers_1.toBigInt)(new Uint8Array(signature.s));
        s = s > ethers_1.N / BigInt(2) ? ethers_1.N - s : s;
        const recoverAddress = (0, ethers_1.recoverAddress)(digest, {
            r: (0, ethers_1.toBeHex)((0, ethers_1.toBigInt)(new Uint8Array(signature.r)), 32),
            s: (0, ethers_1.toBeHex)(s, 32),
            v: 0x1b,
        });
        const address = await this.getAddress();
        return ethers_1.Signature.from({
            r: (0, ethers_1.toBeHex)((0, ethers_1.toBigInt)(new Uint8Array(signature.r)), 32),
            s: (0, ethers_1.toBeHex)(s, 32),
            v: recoverAddress.toLowerCase() !== address.toLowerCase() ? 0x1c : 0x1b,
        });
    }
}
exports.AwsKmsSigner = AwsKmsSigner;
