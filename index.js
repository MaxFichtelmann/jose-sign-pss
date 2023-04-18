#!/usr/bin/env node

const { CompactSign } = require("jose");
const { readFile } = require("node:fs").promises;
const { subtle } = require("node:crypto").webcrypto;

async function main() {
  const keyfile = process.argv[2];
  if (!keyfile) {
    throw new Error("missing keyfile");
  }

  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const payload = Buffer.concat(chunks);

  const privateJwk = JSON.parse(await readFile(keyfile, "utf8"));
  const keysize = Buffer.from(privateJwk.n, "base64").length;

  let alg, hashAlg;
  switch (keysize) {
    case 256:
      alg = "PS256";
      hashAlg = "SHA-256";
      break;
    case 384:
      alg = "PS384";
      hashAlg = "SHA-384";
      break;
    case 512:
      alg = "PS512";
      hashAlg = "SHA-512";
      break;
  }

  const privateKey = await subtle.importKey(
    "jwk",
    privateJwk,
    {
      name: "RSA-PSS",
      hash: {
        name: hashAlg,
      },
    },
    false,
    ["sign"]
  );

  const jws = await new CompactSign(payload)
    .setProtectedHeader({ alg, kid: privateJwk.kid })
    .sign(privateKey);

  console.log(jws);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
