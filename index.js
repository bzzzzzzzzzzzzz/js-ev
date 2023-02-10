import * as umbral from "@nucypher/umbral-pre";
import { reencryptionevidence_e, reencryptionevidence_new } from "@nucypher/umbral-pre/pkg-bundler/umbral_pre_wasm_bg.wasm";
const publicKeyToAddress = require('ethereum-public-key-to-address')
import Web3 from "web3";

let enc = new TextEncoder();
let dec = new TextDecoder("utf-8");

// ALICE Key Generation
let alice_sk = umbral.SecretKey.random();
let alice_pk = alice_sk.publicKey();
let signing_sk = umbral.SecretKey.random();
let signer = new umbral.Signer(signing_sk);
let verifying_pk = signing_sk.publicKey()

// ALICE converts alice pub key into address (needed for evaluation evidence)

let alice_address_str = publicKeyToAddress(Buffer.from(alice_pk.toCompressedBytes())).slice(2)

const fromHexString = (hexString) =>
  Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

let alice_address = fromHexString(alice_address_str)

// BOB Key Generation
let bob_sk = umbral.SecretKey.random();
let bob_pk = bob_sk.publicKey();

// ALICE encrypts data with Alice's public key.
// Invocation of `encrypt()` returns both the ciphertext and a capsule.

let plaintext = "Plaintext message";
let plaintext_bytes = enc.encode(plaintext);

let [capsule, ciphertext] = umbral.encrypt(alice_pk, plaintext_bytes);

// BREAK

let shares = 2; // how many fragments to create
let threshold = 1; // how many should be enough to decrypt
let kfrags = umbral.generateKFrags(
    alice_sk, bob_pk, signer, threshold, shares,
    true, // add the delegating key (alice_pk) to the signature
    true, // add the receiving key (bob_pk) to the signature
    );

// Ursula 0
let cfrag0 = umbral.reencrypt(capsule, kfrags[0]);

// create reencryption evidence

let evidence = new umbral.ReencryptionEvidence(capsule, cfrag0, verifying_pk, alice_pk, bob_pk)

let pointEyCoord = evidence.e.coordinates()[1]
let pointEZxCoord = evidence.ez.coordinates()[0]
let pointEZyCoord = evidence.ez.coordinates()[1]
let pointE1yCoord = evidence.e1.coordinates()[1]
let pointE1HxCoord = evidence.e1h.coordinates()[0]
let pointE1HyCoord = evidence.e1h.coordinates()[1]
let pointE2yCoord = evidence.e2.coordinates()[1]
let pointVyCoord = evidence.v.coordinates()[1]
let pointVZxCoord = evidence.vz.coordinates()[0]
let pointVZyCoord = evidence.vz.coordinates()[1]
let pointV1yCoord = evidence.v1.coordinates()[1]
let pointV1HxCoord = evidence.v1h.coordinates()[0]
let pointV1HyCoord = evidence.v1h.coordinates()[1]
let pointV2yCoord = evidence.v2.coordinates()[1]
let pointUZxCoord = evidence.uz.coordinates()[0]
let pointUZyCoord = evidence.uz.coordinates()[1]
let pointU1yCoord = evidence.u1.coordinates()[1]
let pointU1HxCoord = evidence.u1h.coordinates()[0]
let pointU1HyCoord = evidence.u1h.coordinates()[1]
let pointU2yCoord = evidence.u2.coordinates()[1]
let hashedKFragValidityMessage = evidence.kfragValidityMessageHash
let alicesKeyAsAddress = alice_address
let lostBytesBool = evidence.kfragSignatureV

if (lostBytesBool == false) {
    var lostBytes = new Uint8Array([0x00])
} else {
    var lostBytes = new Uint8Array([0x01])
}

let eval_args = new Uint8Array([
    ...pointEyCoord,
    ...pointEZxCoord,
    ...pointEZyCoord,
    ...pointE1yCoord,
    ...pointE1HxCoord,
    ...pointE1HyCoord,
    ...pointE2yCoord,
    ...pointVyCoord,
    ...pointVZxCoord,
    ...pointVZyCoord,
    ...pointV1yCoord,
    ...pointV1HxCoord,
    ...pointV1HyCoord,
    ...pointV2yCoord,
    ...pointUZxCoord,
    ...pointUZyCoord,
    ...pointU1yCoord,
    ...pointU1HxCoord,
    ...pointU1HyCoord,
    ...pointU2yCoord,
    ...hashedKFragValidityMessage,
    ...alicesKeyAsAddress,
    ...lostBytes,                       
    ...lostBytes,
    ...lostBytes,
    ...lostBytes,
    ...lostBytes,
])

capsule = capsule.toBytesSimple()
cfrag0 = cfrag0.toBytes()



// call eth smart contract deployed to localhost8080...


// Connect to the local Ganache network
const web3 = new Web3(window.ethereum)
  
// Load the JSON file for the smart contract
var contractJSON = require("./build/contracts/ReEncryptionValidator.json");

// Retrieve the ABI from the JSON file
var abi = contractJSON.abi;

// Retrieve the contract address from the JSON file
var contractAddress = contractJSON.networks[5777].address;

// Create a contract object
var contract = new web3.eth.Contract(abi, contractAddress);

// test tx
// const main2 = async () => {
//     var accounts = await web3.eth.requestAccounts();
//     const receiver = '0xf60B527Fd5b61C322a3f2745A1e95dfB229053D6'
//     const sender = accounts[0]
//     web3.eth.sendTransaction({to: receiver, from: sender, value:10000000000000})
// }

// main2();

// convert uint8 array into hex str
capsule = web3.utils.bytesToHex(capsule);
cfrag0 = web3.utils.bytesToHex(cfrag0);
eval_args = web3.utils.bytesToHex(eval_args);

contract.methods.validateCFrag(capsule, cfrag0, eval_args).call()
