const Web3 = require('web3');
const web3 = new Web3("https://mywanwallet.nl/testnet");
const HelloWorld = require('../build/contracts/HelloWorld.json');
const ethPNContract = new web3.eth.Contract(HelloWorld.abi, "0xfdc82b90885ba8fd73b3643d4935527e46cd5574");
async function getBalance(){

    const balance = await ethPNContract.methods.balance().call();
    console.log(balance)
}
getBalance()