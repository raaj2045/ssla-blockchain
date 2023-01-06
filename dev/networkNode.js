const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const Blockchain = require("./blockchain");
const uuid = require("uuid/v1");
const port = process.argv[2];
const rp = require("request-promise");
const sss = require("shamirs-secret-sharing");
const ECCFunctions = require("./util/ecc-functions");
const crypto = require("crypto");
const { signMessage, verifySignature } = require("./util/ecdsa");
let localQca;

const nodeAddress = uuid().split("-").join("");

const blockchain = new Blockchain();

const localKeyShares = [];
const localCertShares = [];

const maxShares = 5;
const threshold = 2;

const eccFunctions = new ECCFunctions({
  prevBlockTimestamp: blockchain.getLastBlock().timestamp,
  maxShares,
  threshold,
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// get entire blockchain
app.get("/blockchain", function (req, res) {
  res.send(blockchain);
});

// create a new transaction
app.post("/transaction", function (req, res) {
  const newTransaction = req.body;
  const blockIndex =
    blockchain.addTransactionToPendingTransactions(newTransaction);
  res.json({ note: `Transaction will be added in block ${blockIndex}.` });
});

// broadcast transaction
app.post("/transaction/broadcast", function (req, res) {
  const newTransaction = blockchain.createNewTransaction(
    req.body.amount,
    req.body.sender,
    req.body.recipient
  );
  blockchain.addTransactionToPendingTransactions(newTransaction);

  const requestPromises = [];
  blockchain.networkNodes.forEach((networkNodeUrl) => {
    const requestOptions = {
      uri: networkNodeUrl + "/transaction",
      method: "POST",
      body: newTransaction,
      json: true,
    };

    requestPromises.push(rp(requestOptions));
  });

  Promise.all(requestPromises).then((data) => {
    res.json({ note: "Transaction created and broadcast successfully." });
  });
});

// mine a block
app.get("/mine", function (req, res) {
  const lastBlock = blockchain.getLastBlock();
  const previousBlockHash = lastBlock["hash"];
  let currentBlockData = {
    transactions: blockchain.pendingTransactions,
    index: lastBlock["index"] + 1,
  };

  let du, Ec, Qu;

  while (
    threshold >= localKeyShares.length &&
    threshold >= localCertShares.length
  ) {
    console.log(
      "combined key =>",
      sss.combine(localKeyShares.map((share) => Buffer.from(share)))
    );

    console.log(
      "combined cert =>",
      sss.combine(localCertShares.map((share) => Buffer.from(share)))
    );

    du = sss
      .combine(localKeyShares.map((share) => Buffer.from(share, "hex")))
      .toString();
    Ec = sss
      .combine(localCertShares.map((share) => Buffer.from(share, "hex")))
      .toString();

    console.log(du);
    console.log(Ec);

    Ec = JSON.parse(Ec, (key, value) => {
      if (typeof value === "string" && value.startsWith("BIGINT::")) {
        return BigInt(value.substr(8));
      }
      return value;
    });

    console.log(Ec);

    du = BigInt(du);

    console.log(du);

    Qu = eccFunctions.getGeneratorPoint().multiplyDA(du);

    console.log(Qu);
  }

  console.log(Qu, du);
  const { signature } = signMessage(Qu.toString(), du, eccFunctions);

  currentBlockData["Ec"] = Ec;
  currentBlockData["signature"] = signature;
  currentBlockData["Qu"] = Qu;

  const blockHash = blockchain.hashBlock(previousBlockHash, currentBlockData);

  const newBlock = blockchain.createNewBlock(
    previousBlockHash,
    blockHash,
    currentBlockData
  );

  const requestPromises = [];
  blockchain.networkNodes.forEach((networkNodeUrl) => {
    const requestOptions = {
      uri: networkNodeUrl + "/receive-new-block",
      method: "POST",
      body: { newBlock: newBlock },
      json: true,
    };

    requestPromises.push(rp(requestOptions));
  });

  Promise.all(requestPromises)
    .then((data) => {
      const requestOptions = {
        uri: blockchain.currentNodeUrl + "/transaction/broadcast",
        method: "POST",
        body: {
          amount: 12.5,
          sender: "00",
          recipient: nodeAddress,
        },
        json: true,
      };

      return rp(requestOptions);
    })
    .then((data) => {
      res.json({
        note: "New block mined & broadcast successfully",
        block: newBlock,
      });
    });
});

// receive new block
app.post("/receive-new-block", function (req, res) {
  const newBlock = req.body.newBlock;

  // Qu = eEc + QCA
  const Ec = newBlock.Ec;

  const Qu = newBlock.Qu;

  const signature = newBlock.signature;

  let e = BigInt(
    "0x" +
      crypto
        .createHash("sha256")
        .update(this.Ec.x.toString() + this.Ec.y.toString())
        .digest("hex")
  );

  let computedQu = Ec.multiplyDA(e).add(localQca);

  if (verifySignature(Qu.toString(), signature, computedQu)) {
    blockchain.chain.push(newBlock);
    blockchain.pendingTransactions = [];
    res.json({
      note: "New block received and accepted.",
      newBlock: newBlock,
    });
  } else {
    res.json({
      note: "New block rejected.",
      newBlock: newBlock,
    });
  }
});

// register a node and broadcast it the network
app.post("/register-and-broadcast-node", function (req, res) {
  const newNodeUrl = req.body.newNodeUrl;
  if (blockchain.networkNodes.indexOf(newNodeUrl) == -1)
    blockchain.networkNodes.push(newNodeUrl);

  const regNodesPromises = [];
  blockchain.networkNodes.forEach((networkNodeUrl) => {
    const requestOptions = {
      uri: networkNodeUrl + "/register-node",
      method: "POST",
      body: { newNodeUrl: newNodeUrl },
      json: true,
    };

    regNodesPromises.push(rp(requestOptions));
  });

  Promise.all(regNodesPromises)
    .then((data) => {
      const bulkRegisterOptions = {
        uri: newNodeUrl + "/register-nodes-bulk",
        method: "POST",
        body: {
          allNetworkNodes: [
            ...blockchain.networkNodes,
            blockchain.currentNodeUrl,
          ],
        },
        json: true,
      };

      return rp(bulkRegisterOptions);
    })
    .then((data) => {
      res.json({ note: "New node registered with network successfully." });
    });
});

// register a node with the network
app.post("/register-node", function (req, res) {
  const newNodeUrl = req.body.newNodeUrl;
  const nodeNotAlreadyPresent =
    blockchain.networkNodes.indexOf(newNodeUrl) == -1;
  const notCurrentNode = blockchain.currentNodeUrl !== newNodeUrl;
  if (nodeNotAlreadyPresent && notCurrentNode)
    blockchain.networkNodes.push(newNodeUrl);

  // after a new node is introduced in the network

  // create keys with the timestamp
  console.log("Generating keys with prev block timestamp");
  const { keyShare, certShare } = eccFunctions.getShares();
  const qca = eccFunctions.getCAPublicKey();

  //  broadcast random key share and cert share for the current block

  const broadcastPromises = [];

  console.log("creating broadcast request of key shares");

  blockchain.networkNodes.forEach((networkNodeUrl) => {
    const requestOptions = {
      uri: networkNodeUrl + "/recieve-shares",
      method: "POST",
      body: {
        certInformation: certShare,
        keyInformation: keyShare,
      },
      json: true,
    };

    broadcastPromises.push(rp(requestOptions));
  });

  console.log("creating broadcast request of QCA");

  blockchain.networkNodes.forEach((networkNodeUrl) => {
    const qcaJSON = JSON.stringify(qca, (key, value) =>
      typeof value === "bigint" ? `BIGINT::${value}` : value
    );

    const requestOptions = {
      uri: networkNodeUrl + "/recieve-qca",
      method: "POST",
      body: {
        Qca: qcaJSON,
      },
      json: true,
    };

    broadcastPromises.push(rp(requestOptions));
  });

  Promise.all(broadcastPromises).then((data) => {
    res.json({
      note: "New node registered successfully. Key Information broadcasted",
    });
  });
});

// register multiple nodes at once
app.post("/register-nodes-bulk", function (req, res) {
  const allNetworkNodes = req.body.allNetworkNodes;
  allNetworkNodes.forEach((networkNodeUrl) => {
    const nodeNotAlreadyPresent =
      blockchain.networkNodes.indexOf(networkNodeUrl) == -1;
    const notCurrentNode = blockchain.currentNodeUrl !== networkNodeUrl;
    if (nodeNotAlreadyPresent && notCurrentNode)
      blockchain.networkNodes.push(networkNodeUrl);
  });

  res.json({ note: "Bulk registration successful." });
});

// consensus
app.get("/consensus", function (req, res) {
  const requestPromises = [];
  blockchain.networkNodes.forEach((networkNodeUrl) => {
    const requestOptions = {
      uri: networkNodeUrl + "/blockchain",
      method: "GET",
      json: true,
    };

    requestPromises.push(rp(requestOptions));
  });

  Promise.all(requestPromises).then((blockchains) => {
    const currentChainLength = blockchain.chain.length;
    let maxChainLength = currentChainLength;
    let newLongestChain = null;
    let newPendingTransactions = null;

    blockchains.forEach((bc) => {
      if (bc.chain.length > maxChainLength) {
        maxChainLength = bc.chain.length;
        newLongestChain = bc.chain;
        newPendingTransactions = bc.pendingTransactions;
      }
    });

    if (
      !newLongestChain ||
      (newLongestChain && !blockchain.chainIsValid(newLongestChain))
    ) {
      res.json({
        note: "Current chain has not been replaced.",
        chain: blockchain.chain,
      });
    } else {
      blockchain.chain = newLongestChain;
      blockchain.pendingTransactions = newPendingTransactions;
      res.json({
        note: "This chain has been replaced.",
        chain: blockchain.chain,
      });
    }
  });
});

// get block by blockHash
app.get("/block/:blockHash", function (req, res) {
  const blockHash = req.params.blockHash;
  const correctBlock = blockchain.getBlock(blockHash);
  res.json({
    block: correctBlock,
  });
});

// get transaction by transactionId
app.get("/transaction/:transactionId", function (req, res) {
  const transactionId = req.params.transactionId;
  const trasactionData = blockchain.getTransaction(transactionId);
  res.json({
    transaction: trasactionData.transaction,
    block: trasactionData.block,
  });
});

// get address by address
app.get("/address/:address", function (req, res) {
  const address = req.params.address;
  const addressData = blockchain.getAddressData(address);
  res.json({
    addressData: addressData,
  });
});

// block explorer
app.get("/block-explorer", function (req, res) {
  res.sendFile("./block-explorer/index.html", { root: __dirname });
});

// recieve shares of cert and keys
app.post("/recieve-shares", (req, res) => {
  const { keyInformation, certInformation } = req.body;
  const keyShareNotAlreadyPresent =
    localKeyShares.indexOf(keyInformation) == -1;
  const certShareNotAlreadyPresent =
    localCertShares.indexOf(certInformation) == -1;
  if (keyShareNotAlreadyPresent) localKeyShares.push(keyInformation);
  if (certShareNotAlreadyPresent) localCertShares.push(certInformation);

  console.log({ localKeyShares, localCertShares });
  res.send({ note: "successfully stored shares" });
});

// recieve Qca
app.post("/recieve-qca", (req, res) => {
  const { Qca } = req.body;

  // Deserialize
  localQca = JSON.parse(Qca, (key, value) => {
    if (typeof value === "string" && value.startsWith("BIGINT::")) {
      return BigInt(value.substr(8));
    }
    return value;
  });

  res.send({ note: "successfully stored Qca" });
});

app.listen(port, function () {
  console.log(`Listening on port ${port}...`);
});
