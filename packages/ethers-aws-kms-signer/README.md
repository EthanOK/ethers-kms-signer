# ethers-aws-kms-signer

The @aws-sdk/client-kms integration with ethers@v6 signer

## Feature

- ethers@v6 signer compatible

## Install

```sh
# npm install @cuonghx.gu-tech/ethers-aws-kms-signer
npm install ethers-aws-kms-signer-v6
```

## Usage

```javascript
  signer = new AwsKmsSigner({
    keyId: process.env.TEST_KMS_KEY_ID!,
    region: process.env.TEST_KMS_REGION_ID!,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
    },
  });
  
  # add sign()
  //  digest type is bytes32
  const signedMessage = await signer.sign(digest);
```
