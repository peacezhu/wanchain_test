### Here are my questions,plwase read them
```javascript
pragma solidity >=0.5.0 <0.6.0;

// import "./lib/ECDSA.sol";
// import "./lib/ERC20.sol";
contract ERC20 {
    function totalSupply() public view returns (uint);
    function balanceOf(address tokenOwner) public view returns (uint balance);
    function allowance(address tokenOwner, address spender) public view returns (uint remaining);
    function transfer(address to, uint tokens) public;
    function approve(address spender, uint tokens) public;
    function transferFrom(address from, address to, uint tokens) public;

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}

// Safe token action
library SafeERC20 {
    function safeTransfer(
        ERC20 token,
        address to,
        uint256 value
    ) 
        internal
    {
        token.transfer(to, value);
    }

    function safeTransferFrom(
        ERC20 token,
        address from,
        address to,
        uint256 value
    )
        internal
    {
        token.transferFrom(from, to, value);
    }

    function safeApprove(
        ERC20 token,
        address spender,
        uint256 value
    ) 
        internal
    {
        token.approve(spender, value);
    }
}

library ECDSA {

/**
  * @dev Recover signer address from a message by using their signature
  * @param hash bytes32 message, the hash is the signed message. What is recovered is the signer address.
  * @param signature bytes signature, the signature is generated using web3.eth.sign()
  */
function recover(bytes32 hash, bytes memory signature)
    internal
    pure
    returns (address)
{
    bytes32 r;
    bytes32 s;
    uint8 v;

    // Check the signature length
    if (signature.length != 65) {
        return (address(0));
    }

    // Divide the signature in r, s and v variables
    // ecrecover takes the signature parameters, and the only way to get them
    // currently is to use assembly.
    // solium-disable-next-line security/no-inline-assembly
    assembly {
        r := mload(add(signature, 0x20))
        s := mload(add(signature, 0x40))
        v := byte(0, mload(add(signature, 0x60)))
    }

    // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
    if (v < 27) {
        v += 27;
    }

    // If the version is correct return the signer address
    if (v != 27 && v != 28) {
        return (address(0));
    } else {
        // solium-disable-next-line arg-overflow
        return ecrecover(hash, v, r, s);
    }
}

    /**
    * toEthSignedMessageHash
    * @dev prefix a bytes32 value with "\x19Ethereum Signed Message:"
    * and hash the result
    */
    function toEthSignedMessageHash(bytes32 hash)
      internal
      pure
      returns (bytes32)
    {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
    }
}


contract OnchainPayment {
    using SafeERC20 for ERC20;

    /* States */

    address payable public provider;
    //address to receive token
    address payable public receiver;
    // receiver => tokenAddress => providerWithdraw
    mapping (address => mapping (address => uint256)) public providerWithdrawMap;
    // channel counter
    uint256 public counter;
    // user => tokenAddress => counter
    mapping (address => mapping (address => uint256)) public channelCounterMap;
    // channelID => channel
    mapping (bytes32 => Channel) public channelMap;
    struct Channel {
        // 0 = not-exist or settled
        // 1 = open
        // 2 = closing
        uint8 status;
        address payable user;
        //is user close channel
        bool isCloser;
        //update proof 限制的时间
        uint256 settleBlock;
        // 0x0 if eth channel
        address token;
        //user totle deposit
        uint256 deposit;
        //  proof of user
        uint256 userTransferAmount;
        uint256 userNonce;
    }
    uint256 public settleWindowMin;
    uint256 public settleWindowMax;


    // EIP712
    bytes32 public DOMAIN_SEPERATOR;
    bytes32 public constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(bytes32 channelID,uint256 balance,uint256 nonce,bytes32 additionalHash)"
    );
    bytes32 public constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /* Constructor */

    constructor (
        address _provider,
        address _receiver,
        uint256 _settleWindowMin,
        uint256 _settleWindowMax,
        uint256 _chainID
    )
        public
    {
        require(_settleWindowMin > 0, "settleWindowMin should positive");
        require(_settleWindowMax > _settleWindowMin, "settleWindowMax should greater than settleWindowMin");
        provider = address(uint160(_provider));
        receiver = address(uint160(_receiver));
        settleWindowMin = _settleWindowMin;
        settleWindowMax = _settleWindowMax;
        DOMAIN_SEPERATOR = keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256("litexlayer2"),
                keccak256("1"),
                _chainID,
                address(this))
        );
    }
    // Modifiers
    modifier isChannelOpened (bytes32 channelID) {
        require(channelMap[channelID].status == 1, "channel should be open");
        _;
    }
    modifier isChannelClosed (bytes32 channelID) {
        require(channelMap[channelID].status == 2, "channel should be closed");
        _;
    }
    modifier validSettleWindow (uint256 settleWindow) {
        require(settleWindow <= settleWindowMax && settleWindow >= settleWindowMin, "invalid settleWindow");
        _;
    }
    modifier commitBlockValid (uint256 lastCommitBlock) {
        require(block.number <= lastCommitBlock, "commit block expired");
        _;
    }

    /* Public Functions */
    //用户开通道
    function openChannel (
        uint256 settleWindow,
        address token,
        uint256 deposit
    )
        public
        payable
        validSettleWindow(settleWindow)
    {
        require(channelCounterMap[msg.sender][token] == 0, "channel already exist");
        counter += 1;
        channelCounterMap[msg.sender][token] = counter;
        //开通道
        bytes32 channelID = getChannelID(msg.sender,token);
        Channel storage channel = channelMap[channelID];
        channel.status = 1;
        channel.user = msg.sender;
        channel.token = token;
        channel.settleBlock = settleWindow;
        //向通道充值
        if (token == address(0x0)) {
            require(msg.value > 0, "user should deposit eth");
            channel.deposit = uint256(msg.value);
        } else {
            require(deposit > 0, "user should deposit token");
            ERC20(token).safeTransferFrom(msg.sender, address(this), deposit);
            channel.deposit = deposit;
        }

        emit ChannelOpened (
            channel.user,
            token,
            channel.deposit,
            settleWindow,
            channelID
        );

    }

    //用户充值
    function userDeposit (
        bytes32 channelID,
        uint256 totalDeposit
    )
        public
        payable
        isChannelOpened(channelID)
    {
        Channel storage channel = channelMap[channelID];
        uint256 newDeposit;
        if (channel.token == address(0x0)) {
            require(msg.value > 0, "invalid deposit");
            newDeposit = uint256(msg.value);
            channel.deposit += uint256(msg.value);
        } else {
            newDeposit = totalDeposit-channel.deposit;
            require(newDeposit > 0, "new deposit should greater than old deposit");
            ERC20(channel.token).safeTransferFrom(msg.sender, address(this), newDeposit);
            channel.deposit = totalDeposit;
        }
        emit UserDeposited (
            channelID,
            newDeposit,
            channel.deposit
        );
    }

    function providerWithdraw (
        bytes32 channelID,
        uint256 userTransferAmount,
        uint256 userNonce,
        bytes32 additionalHash,
        bytes memory userSignature,
        bool isOpenNewChannel
    )
        public
        isChannelOpened(channelID)
    {
        //如果开新通道，需要userBalance and userNonce大于0
        if( isOpenNewChannel ){
            require(userTransferAmount > 0 && userNonce > 0,"userBalance and userNonce should be positive");
        }
        require(msg.sender == provider, "only provider can trigger");
        //更改通道状态
        Channel storage channel = channelMap[channelID];
        channel.status = 0;
        channel.isCloser == false;
        //有交易验签
        if(userTransferAmount>0 || userNonce>0){
            //验签
            uint8 recoveredUser = recoverBalanceSignature (
                channelID,
                userTransferAmount,
                userNonce,
                additionalHash,
                channel.user,
                userSignature
            );
            if(recoveredUser == 1) {
                //更新nonce和balance
                if(userNonce > 0) {
                    channel.userTransferAmount = userTransferAmount;
                    channel.userNonce = userNonce;
                }
            }else {
                revert("invalid user signature");
            }
        }

        //计算通道数额分配
        // require(userBalance <= channel.deposit, "channel insufficient funds");
        uint256 userTransferred = safeSub(channel.deposit,userTransferAmount);
        uint256 providerRegain = safeSub(channel.deposit,userTransferred);
        providerWithdrawMap[receiver][channel.token] += providerRegain;

        //给receiver转账
        if(providerRegain > 0) {
            if(channel.token == address(0x0)) {
                address(receiver).transfer(providerRegain);
            }else {
                ERC20(channel.token).safeTransfer(receiver,providerRegain);
            }
        }
        delete channelCounterMap[channel.user][channel.token];
        if( isOpenNewChannel ) {
            //开通道
            bytes32 newChannelID = providerOpenChannel(
                channel.user,
                channel.settleBlock,
                channel.token,
                userTransferred
            );
            emit ProviderWithdrawed (
                channelID,
                userTransferAmount,
                userNonce,
                isOpenNewChannel,
                channel.settleBlock,
                userTransferred,
                newChannelID
            );
        }else {
            //给用户转账
            if(userTransferred > 0) {
                if(channel.token == address(0x0)) {
                    address(channel.user).transfer(userTransferred);
                }else {
                    ERC20(channel.token).safeTransfer(channel.user,userTransferred);
                }
            }
            emit ProviderWithdrawed (
                channelID,
                userTransferAmount,
                userNonce,
                isOpenNewChannel,
                channel.settleBlock,
                userTransferred,
                "0x0"
            );
        }
        delete channelMap[channelID];
    }

    // 用户协商关
    function cooperativeSettle(
        bytes32 channelID,
        uint256 balance,
        uint256 lastCommitBlock,
        bytes memory providerSignature
    )
        public
        commitBlockValid(lastCommitBlock)
        isChannelOpened(channelID)
    {
        Channel storage channel = channelMap[channelID];
        require(channel.status == 1, "channel should be open");
        require(msg.sender == channel.user, "only user can trigger");
        // 验签
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                address(this),
                channelID,
                balance,
                lastCommitBlock
            )
        );
        require(ECDSA.recover(messageHash, providerSignature) == provider, "invalid provider signature");
        //计算通道数额分配
        require(balance <= channel.deposit, "channel insufficient funds");
        uint256 providerRegain = safeSub(channel.deposit,balance);
        uint256 userTransferred = safeSub(channel.deposit, providerRegain);
        //给receiver转账
        if(providerRegain > 0) {
            providerWithdrawMap[receiver][channel.token] += providerRegain;
            if(channel.token == address(0x0)) {
                address(receiver).transfer(providerRegain);
            }else {
                ERC20(channel.token).safeTransfer(receiver,providerRegain);
            }
        }
        //给user转账
        if(userTransferred > 0) {
            if( channel.token == address(0x0)) {
                address(channel.user).transfer(userTransferred);
            }else {
                ERC20(channel.token).safeTransfer(channel.user,userTransferred);
            }
        }
        delete channelCounterMap[channel.user][channel.token];
        delete channelMap[channelID];
        emit CooperativeSettled (
            channel.user,
            channelID,
            channel.token,
            balance,
            providerRegain,
            lastCommitBlock
        );
    }

    function userCloseChannel (
        bytes32 channelID,
        uint256 userTransferAmount,
        uint256 userNonce
    )
        public
        isChannelOpened(channelID)
    {
        Channel storage channel = channelMap[channelID];
        require(msg.sender == channel.user, "only user can trigger");
        //设置通道状态
        channel.status = 2;
        channel.settleBlock += uint256(block.number);
        channel.isCloser = true;
        channel.userTransferAmount = userTransferAmount;
        channel.userNonce = userNonce;
        emit UserClosedChannel (
            channelID,
            userTransferAmount,
            userNonce
        );
    }


    function updateProofAndSettleChannel (
        bytes32 channelID,
        uint256 userTransferAmount,
        uint256 userNonce,
        bytes32 additionalHash,
        bytes memory userSignature
    )
        public
        // isChannelClosed(channelID)
    {
        require(msg.sender == provider, "only provider can trigger");
        Channel storage channel = channelMap[channelID];
        //当userBalance、userNonce任意一个不等时，更新通道数据
        if(channel.userTransferAmount != userTransferAmount || channel.userNonce != userNonce) {
            uint8 recoveredUser = recoverBalanceSignature (
                channelID,
                userTransferAmount,
                userNonce,
                additionalHash,
                channel.user,
                userSignature
            );
            if(recoveredUser == 1){
                channel.userTransferAmount = userTransferAmount;
                channel.userNonce = userNonce;
            }
        }
        uint256 userTransferred;
        uint256 providerRegain;
        (userTransferred,providerRegain) = settlingChannel(channelID);
        emit UpdatedProofAndSettledChannel(
            channelID,
            userTransferAmount,
            userNonce,
            userTransferred,
            providerRegain
        );
    }


    function settleChannel (
        bytes32 channelID
    )
        public
    {
        uint256 userTransferred;
        uint256 providerRegain;
        (userTransferred,providerRegain) = settlingChannel(channelID);
        emit  SettledChannel(
            channelID,
            userTransferred,
            providerRegain
        );
    }

    function getChannelID (
        address user,
        address token
    )
        public
        view
        returns (bytes32)
    {
        require(user != address(0x0), "invalid input");
        uint256 _counter = channelCounterMap[user][token];
        require(_counter != 0, "channel does not exist");
        return keccak256((abi.encodePacked(user,token,_counter)));
    }

    function setReceiver(address _receiver) public {
        require(msg.sender == receiver, "should receiver call!");
        receiver = address(uint160(_receiver));
        emit  SetReceiver(
            receiver,
            _receiver
        );
    }

    //  /**
    //  *  Events
    //  */

    event ChannelOpened (
        address indexed user,
        address indexed token,
        uint256 totalDeposit,
        uint256 settleWindow,
        bytes32 channelID
    );
    event UserDeposited (
        bytes32 indexed channelID,
        uint256 newDeposit,
        uint256 totalDeposit
    );

    event ProviderWithdrawed (
        bytes32 channelID,
        uint256 userTransferAmount,
        uint256 userNonce,
        bool isOpenNewChannel,
        uint256 settleWindow,
        uint256 userTransferred,
        bytes32 newChannelID
    );
    event CooperativeSettled (
        address indexed user,
        bytes32 indexed channelID,
        address token,
        uint256 balance,
        uint256 providerRegain,
        uint256 lastCommitBlock
    );
    event UserClosedChannel (
        bytes32 indexed channelID,
        uint256 userTransferAmount,
        uint256 userNonce
    );
    event UpdatedProofAndSettledChannel(
        bytes32 indexed channelID,
        uint256 userTransferAmount,
        uint256 userNonce,
        uint256 userTransferred,
        uint256 providerRegain
    );

    event SettledChannel(
        bytes32 indexed channelID,
        uint256 transferToUserAmount,
        uint256 providerRegain
    );
    event  SetReceiver(
        address oldReceiver,
        address newReceiver
    );

    function settlingChannel(
        bytes32 channelID
    )
        internal
        isChannelClosed(channelID)
        returns(uint256,uint256)
    {
        Channel storage channel = channelMap[channelID];
        //provider调用无超时设定
        if(msg.sender != provider){
            require(block.number > channel.settleBlock, "commit block expired");
        }
        //通道金额分配
        // require(channel.userBalance <= channel.deposit, "channel insufficient funds");
        uint256 userTransferred = safeSub(channel.deposit, channel.userTransferAmount);
        uint256 providerRegain = safeSub(channel.deposit, userTransferred);
        providerWithdrawMap[receiver][channel.token] += providerRegain;
        //给用户转账
        if(userTransferred > 0) {
            if(channel.token == address(0x0)) {
                address(channel.user).transfer(userTransferred);
            }else {
                ERC20(channel.token).safeTransfer(channel.user,userTransferred);
            }
        }
        //给provider转账
        if(providerRegain > 0) {
            if(channel.token == address(0x0)) {
                address(receiver).transfer(providerRegain);
            }else {
                ERC20(channel.token).safeTransfer(receiver,providerRegain);
            }
        }
        //删除通道
        delete channelCounterMap[channel.user][channel.token];
        delete channelMap[channelID];
        return (userTransferred,providerRegain);
    }

    function transferHash(
        bytes32 channelID,
        uint256 balance,
        uint256 nonce,
        bytes32 additionalHash
    )
        private
        view
        returns(bytes32,bytes32)
    {
        bytes32 hash = keccak256(
            abi.encode(
                TRANSFER_TYPEHASH,
                channelID,
                balance,
                nonce,
                additionalHash
            )
        );
        bytes32 hash1 = keccak256(
            abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPERATOR,
            hash
        ));

        bytes32 hash2 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash1));

        return (hash1, hash2);
    }

    function recoverBalanceSignature (
        bytes32 channelID,
        uint256 balance,
        uint256 nonce,
        bytes32 additionalHash,
        address user,
        bytes memory signature
    )
        internal
        view
        returns (uint8)
    {
        bytes32 hash1;
        bytes32 hash2;
        (hash1, hash2) = transferHash(channelID, balance, nonce, additionalHash);

        address recoveredSignature1 = ECDSA.recover(hash1, signature);
        if( recoveredSignature1 == user ){
            return 1;
        }
        if( recoveredSignature1 == provider ){
            return 2;
        }

        address recoveredSignature2 = ECDSA.recover(hash2, signature);
        if( recoveredSignature2 == user ){
            return 1;
        }
        if( recoveredSignature2 == provider ){
            return 2;
        }

        return 0;
    }

    function providerOpenChannel(
        address user,
        uint256 settleWindow,
        address token,
        uint256 totalDeposit
    )
        internal
        validSettleWindow(settleWindow)
        returns(bytes32)
    {
        require(msg.sender == provider, "msg.sender should be provider");
        require(channelCounterMap[user][token] == 0, "channel already exist");

        counter += 1;
        channelCounterMap[user][token] = counter;
        bytes32 channelID = getChannelID(user,token);

        Channel storage channel = channelMap[channelID];
        channel.status = 1;
        channel.user = address(uint160(user));
        channel.token = token;
        channel.settleBlock = settleWindow;
        channel.deposit = totalDeposit;
        return channelID;
    }


    function safeSub(
        uint256 a,
        uint256 b
    )
        internal
        pure
        returns (uint256)
    {
        return a > b ? a - b : 0;
    }

    function safeAdd(
        uint256 a,
        uint256 b
    )
        internal
        pure
        returns (uint256)
    {
        uint256 c = a + b;
        require(c >= a, "add failed");
        return c;
    }

}
```

