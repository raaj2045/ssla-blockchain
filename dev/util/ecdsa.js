const crypto = require("crypto");
const Point = require("./ecc-curve");
const bigintModArith = require("bigint-mod-arith");

const n = 180n;

const signMessage = (message, privateKey, eccFunctions) => {
  const h = BigInt(
    "0x" + crypto.createHash("sha256").update(message).digest("hex")
  );

  const k = h + privateKey;
  const R = eccFunctions.getGeneratorPoint().multiplyDA(k);
  const r = R.x;

  const s = (bigintModArith.modInv(k, n) * (h + r * privateKey)) % n;

  return { signature: { r, s } };
};

const verifySignature = (message, signature, publicKey) => {
  const s1 = bigintModArith.modInv(signature.s, n);

  const h = BigInt(
    "0x" + crypto.createHash("sha256").update(message).digest("hex")
  );

  const R1 = eccFunctions
    .getGeneratorPoint()
    .multiplyDA(h * s1)
    .add(publicKey.multiplyDA(signature.r * s1));

  console.log(r1, signature);

  const r1 = R1.x;
  return signature.r === r1;
};

module.exports = { signMessage, verifySignature };
