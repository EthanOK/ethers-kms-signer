import { expect } from "chai";
import dotenv from "dotenv";

import { AwsKmsSigner } from "../src/aws-kms-signer";
import { ethers, recoverAddress, solidityPackedKeccak256 } from "ethers";

dotenv.config();

context("AwsKmsSigner", () => {
  let signer: AwsKmsSigner;

  describe("explicit credentials", () => {
    beforeEach(() => {
      signer = new AwsKmsSigner({
        keyId: process.env.TEST_KMS_KEY_ID!,
        region: process.env.TEST_KMS_REGION_ID!,
        credentials: {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
      });
    });

    it("Should return correct public key", async () => {
      expect(await signer.getAddress()).to.eql(
        "0xc1ccb193b2ded11dd25342008fc8449621732285"
      );
    });
  });

  describe("AWS SSO", () => {
    it("Should get sign a message", async () => {
      signer = new AwsKmsSigner({
        credentials: {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
        keyId: process.env.TEST_KMS_KEY_ID!,
        region: process.env.TEST_KMS_REGION_ID!,
      });
      const testMessage = "test";
      const publicAddress = await signer.getAddress();

      const signature = await signer.signMessage(testMessage);

      console.log(signature);
      

      const eip191Hash = solidityPackedKeccak256(
        ["string", "string"],
        ["\x19Ethereum Signed Message:\n4", testMessage]
      );

      const recoveredAddress = recoverAddress(eip191Hash, signature);

      expect(recoveredAddress.toLowerCase()).to.equal(
        publicAddress.toLowerCase()
      );
    });
    it("Should get sign a message", async () => {
      signer = new AwsKmsSigner({
        credentials: {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
        keyId: process.env.TEST_KMS_KEY_ID!,
        region: process.env.TEST_KMS_REGION_ID!,
      });
      const testMessage = "test";
      const publicAddress = await signer.getAddress();

      const eip191Hash = solidityPackedKeccak256(
        ["string", "string"],
        ["\x19Ethereum Signed Message:\n4", testMessage]
      );

      const signature = await signer.sign(eip191Hash);
      console.log(signature)
      

      const recoveredAddress = recoverAddress(eip191Hash, signature);

      expect(recoveredAddress.toLowerCase()).to.equal(
        publicAddress.toLowerCase()
      );
    });
  });
});
