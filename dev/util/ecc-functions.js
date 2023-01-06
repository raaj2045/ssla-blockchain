const crypto = require("crypto");
const Point = require("./ecc-curve");
const sss = require("shamirs-secret-sharing");

class ECCFunctions {
  constructor({ prevBlockTimestamp, maxShares, threshold }) {
    // G x, y values taken from official secp256k1 document
    const CURVE = {
      Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
      Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
    };

    this.G = new Point(CURVE.Gx, CURVE.Gy);

    const n = 180;
    const dca = 112;

    prevBlockTimestamp = prevBlockTimestamp.toString().split("");

    const half = Math.ceil(prevBlockTimestamp.length / 2);

    const firstHalfTimestamp =
      parseInt(prevBlockTimestamp.slice(0, half).join("")) % n;

    const secondHalfTimestamp =
      parseInt(prevBlockTimestamp.slice(-half).join("")) % n;

    //random  1 <= ru <= n-1
    const ru = BigInt(firstHalfTimestamp);

    // Ec point Ru

    const Ru = this.G.multiplyDA(ru);

    // random  1 <= ru <= n-1
    const rca = BigInt(secondHalfTimestamp);

    // Certificate Ec
    this.Ec = Ru.add(this.G.multiplyDA(rca));

    // Calculate hash e for Ec
    const e = BigInt(
      "0x" +
        crypto
          .createHash("sha256")
          .update(this.Ec.x.toString() + this.Ec.y.toString())
          .digest("hex")
    );

    // Integer S used to compute private Key
    const S = e * rca + (BigInt(dca) % BigInt(n));

    // Private key du

    const du = e * ru + (S % BigInt(n));

    // Generating shares from cert and key

    //Yeah that’s true , if you can use the value Qca=duG - eCertu
    const temp = this.Ec.multiplyDA(e);
    temp.y -= BigInt(2) * temp.y;

    this.Qca = this.G.multiplyDA(BigInt(du)).add(temp);

    const ecJSON = JSON.stringify(this.Ec, (key, value) =>
      typeof value === "bigint" ? `BIGINT::${value}` : value
    );

    const certBuffer = Buffer.from(ecJSON);

    this.certShares = sss.split(certBuffer, {
      shares: maxShares,
      threshold,
      random: (size) => {
        return Buffer.from("a");
      },
    });

    console.log(this.certShares);
    // const recovered = sss.combine(shares.slice(3, 7))

    const keyBuffer = Buffer.from(du.toString());
    this.keyShares = sss.split(keyBuffer, {
      shares: maxShares,
      threshold,
      random: (size) => {
        return Buffer.from("a");
      },
    });

    console.log("cert shares =>", this.certShares);
    console.log("key shares =>", this.keyShares);

    let keyShare =
      this.keyShares[
        Math.floor(Math.random() * this.keyShares.length)
      ].toString("hex");
    let certShare =
      this.certShares[
        Math.floor(Math.random() * this.certShares.length)
      ].toString("hex");
    console.log(keyShare, certShare);
    console.log(Buffer.from(keyShare, "hex"));
    console.log(Buffer.from(certShare, "hex"));
  }

  getShares() {
    return {
      keyShare:
        this.keyShares[
          Math.floor(Math.random() * this.keyShares.length)
        ].toString("hex"),
      certShare:
        this.certShares[
          Math.floor(Math.random() * this.certShares.length)
        ].toString("hex"),
    };
  }

  getCAPublicKey() {
    return this.Qca;
  }

  getGeneratorPoint() {
    return this.G;
  }
}

module.exports = ECCFunctions;
