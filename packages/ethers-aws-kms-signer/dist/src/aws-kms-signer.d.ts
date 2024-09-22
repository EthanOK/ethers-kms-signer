import { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@smithy/types";
import { AbstractSigner, BytesLike, Provider, TransactionRequest, TypedDataDomain, TypedDataField } from "ethers";
export type EthersAwsKmsSignerConfig = {
    credentials: AwsCredentialIdentityProvider | AwsCredentialIdentity;
    region: string;
    keyId: string;
};
export declare class AwsKmsSigner<P extends null | Provider = null | Provider> extends AbstractSigner {
    private config;
    private client;
    address: string;
    constructor(config: EthersAwsKmsSignerConfig, provider?: P);
    connect(provider: Provider | null): AwsKmsSigner;
    getAddress(): Promise<string>;
    signTransaction(tx: TransactionRequest): Promise<string>;
    signMessage(message: string | Uint8Array): Promise<string>;
    sign(digest: BytesLike): Promise<string>;
    signTypedData(domain: TypedDataDomain, types: Record<string, TypedDataField[]>, value: Record<string, any>): Promise<string>;
    private _createKMSClient;
    private _sign;
}
