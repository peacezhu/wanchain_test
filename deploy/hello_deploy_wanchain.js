const Web3 = require('web3');
const web3 = new Web3("https://mywanwallet.nl/testnet");
const Tx = require('wanchainjs-tx')


const HelloWorld = require('../build/contracts/HelloWorld.json');
constructArgs = [];
const privateKey = "0x2C32580485EE0D134DE5BDAAA2B8E23FC8B1F10A8702FB2B281EEF717B06568B";
const account = web3.eth.accounts.privateKeyToAccount(privateKey) 
web3.eth.accounts.wallet.add(account) // add account to cita

const deploy = async () => {
  let address = web3.eth.accounts.wallet[0].address;
  const MyContract = new web3.eth.Contract(HelloWorld.abi);
  const bytecodeWithParam = await MyContract.deploy({
    data: HelloWorld.bytecode,
    arguments: constructArgs,
  }).encodeABI();
  const nonce = await web3.eth.getTransactionCount(address);
  let transactionHash = await executeTransaction(bytecodeWithParam, nonce);
  let receipt;
  let repeatTime = 0;
  while (repeatTime++ < 100) {
    try {
      receipt = await web3.eth.getTransactionReceipt(transactionHash);
      if (receipt != null) {
        break;
      }
    } catch (error) {

    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  if(receipt != null){
    console.log("receipt",receipt);
    console.log("receipt",receipt.contractAddress.toLowerCase());
  }
};


async function executeTransaction(bytecodeWithParam, nonce) {
  var rawTransaction = {
    Txtype: '0x01',
    nonce: web3.utils.toHex(nonce),
    from: account.address,
    gasPrice: '0x2a600b9c00',
    gasLimit: '0x152082',
    value: "0x0",
    data: bytecodeWithParam,
    chainId: 3
  };
  var privKey = Buffer.from(privateKey.substr(2), 'hex');
  var tx = new Tx(rawTransaction);
  tx.sign(privKey);
  var serializedTx = tx.serialize();
  return new Promise((resolve, reject) => {
    web3.eth.sendSignedTransaction('0x' + serializedTx.toString('hex'))
      .on('transactionHash', (transactionHash => {
        resolve(transactionHash)
      }))
      .on('error', (err) => {
        reject(err);
      });
  });
}

deploy();