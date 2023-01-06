const axios = require("axios");

(async () => {
  await axios.post("http://localhost:3001/register-and-broadcast-node", {
    newNodeUrl: "http://localhost:3001",
  });
  await axios.post("http://localhost:3001/register-and-broadcast-node", {
    newNodeUrl: "http://localhost:3002",
  });
  await axios.post("http://localhost:3001/register-and-broadcast-node", {
    newNodeUrl: "http://localhost:3003",
  });
  await axios.post("http://localhost:3001/register-and-broadcast-node", {
    newNodeUrl: "http://localhost:3004",
  });
})();
