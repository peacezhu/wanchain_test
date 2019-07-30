const Web3 = require('web3');
const Tx = require('wanchainjs-tx')

const OnchainPayment = require('../build/contracts/OnchainPayment.json');
const config = require('./conf.json');

const [gasprice,gaslimit] =[config.gasPrice.onchain,config.gasLimit.onchain];
const chain = config.wanchain;//https://mywanwallet.nl/testnet
let constructArgs = config.onchain_constructArgs;
// "onchain_constructArgs": {
//     "provider":"0xb7c0c4928b33d1D9a65672FCD056450186F910E1",
//     "receiver":"0x4D359d89F0208b24462846B99a2F1ae6727A5F76",
//     "settleWindowMin":1,
//     "settleWindowMax":9,
//     "chainID":3
// }
constructArgs = [
  constructArgs.provider.toLowerCase(),
  constructArgs.receiver.toLowerCase(),
  constructArgs.settleWindowMin,
  constructArgs.settleWindowMax,
  constructArgs.chainID
];

const privateKey = chain.privateKey;
const web3 = new Web3(Web3.givenProvider || chain.provider);
const account = web3.eth.accounts.privateKeyToAccount(privateKey) // create account by private key from config
web3.eth.accounts.wallet.add(account) 

const deploy = async () => {
  console.log("start wanchain deploy");
  let address = web3.eth.accounts.wallet[0].address;
  const MyContract = new web3.eth.Contract(OnchainPayment.abi);
  const nonce = await web3.eth.getTransactionCount(address);
  const bytecodeWithParam = await MyContract.deploy({
    data: OnchainPayment.bytecode,
    arguments: constructArgs,
  }).encodeABI();
  // get transactionHash to find contractAddress
  let transactionHash = await executeTransaction(bytecodeWithParam, nonce);
  // console.log('transactionHash:', transactionHash);
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
    console.log(receipt.contractAddress)
    console.log(receipt.contractAddress.toLowerCase())
    return receipt.contractAddress;
  }
};


async function executeTransaction(bytecodeWithParam, nonce) {
  var rawTransaction = {
    Txtype: '0x01',
    "from": account.address,
    "nonce": "0x" + nonce.toString(16),
    "gasPrice": web3.utils.toHex(gasprice * 1e9),
    "gasLimit": web3.utils.toHex(gaslimit),
    // "to": contractAddress,
    // "value": "0x0",
    "data": bytecodeWithParam,
    // "chainId": chainId
    chainId: 3
  };
  var privKey = Buffer.from(privateKey.substr(2), 'hex');
  var tx = new Tx(rawTransaction);
  tx.sign(privKey);
  var serializedTx = tx.serialize();
  // console.log('serializedTx', serializedTx);

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


// web3.eth.isSyncing().then(console.log);
deploy();
// module.exports = {
//   deploy
// }

// deploy();