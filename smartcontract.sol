// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.5.8;

contract Private13 {
    bytes32 h1 = 0x6c5578a76a6c6c75fc63936bb66e000c278f67fb769cec12ab206aefd86d9c7d;
    bytes32 h2 = 0xe035ae8f570e6f6ad0bee98bcf176af066c8913ac721af5107a16a41a40e7c8a;
    bytes32 h3 = 0x1e22ed11915680610b2093e5abe9e4c937866cec00a12bb725f32c5805eccead;
    bytes32 h4 = 0x0f56344fff12664763cb72542efbe48b415cbbddd9e5f6526df58a33e10efa9c;
    bytes32 h5 = 0x0eb8ce29568278db8c938683324721e23752576693028b673374afde6839bbd4;
    bytes32 h6 = 0x3a87b5be246441cb4258000db1b44b0d1ea84fda156d84c309c7c820e4d1c944;
    bytes32 h7 = 0x7933e9f896cf86f687579cfae925c8f64903c8a697881648b1ae5a03c93f6621;

    bytes32 rh1 = 0x6c5578a76a6c6c75fc63936bb66e000c278f67fb769cec12ab206aefd86d9c7d;
    bytes32 rh2 = 0xe035ae8f570e6f6ad0bee98bcf176af066c8913ac721af5107a16a41a40e7c8a;
    bytes32 rh3 = 0x1e22ed11915680610b2093e5abe9e4c937866cec00a12bb725f32c5805eccead;
    bytes32 rh4 = 0x0f56344fff12664763cb72542efbe48b415cbbddd9e5f6526df58a33e10efa9c;
    bytes32 rh5 = 0x0eb8ce29568278db8c938683324721e23752576693028b673374afde6839bbd4;
    bytes32 rh6 = 0x3a87b5be246441cb4258000db1b44b0d1ea84fda156d84c309c7c820e4d1c944;
    bytes32 rh7 = 0x7933e9f896cf86f687579cfae925c8f64903c8a697881648b1ae5a03c93f6621;

    bytes sig0;
    bytes sig1;
    bytes sig2;
    bytes sig3;
    bytes sig4;
    bytes sig5;
    bytes sig6;
    bytes sig7;
    bytes sig8;
    bytes sig9;

    uint nsigs = 0;

    bool sig0ready = false;
    bool sig1ready = false;
    bool sig2ready = false;
    bool sig3ready = false;
    bool sig4ready = false;
    bool sig5ready = false;
    bool sig6ready = false;
    bool sig7ready = false;
    bool sig8ready = false;
    bool sig9ready = false;

    uint normalizedPriceBase = 0;

    bool depositComplete;

    // Volga
    address payable client_address = 0xF770DcDEDA80AD310A0c7426fB136D0d43263196;
    address payable merchant_address = 0xe0c976f648dC743469943D8bc0d191f28aa016F4;

    address payable bro0 = 0x5300B38EbDBEFFb2296409793de4Bf390f2e7b5B;
    address payable bro1 = 0xe3c70fEfB6f4454d200aC4e27F5c86EEd284D0Aa;
    address payable bro2 = 0x60711202E9373b78b9fa834067cC101fE1603326;
    address payable bro3 = 0x1D57967CF0Ccd871c0277a09Fb48270E29A671AA;
    address payable bro4 = 0x68e49B7c8F1BF427fdc346877D908036475d4ff8;
    address payable bro5 = 0x7a1524de177172Ab7926037399B56e79450AD065;
    address payable bro6 = 0xf411A8E609E6c6824a319D560FCF090DF29D3F8d;
    address payable bro7 = 0xCdB9F097482D8627A7428AB56819C24960A57Da4;
    address payable bro8 = 0x52Cc4178f484FE591a0E85259a3e7829cCF2dD80;
    address payable bro9 = 0xF5577F50B1E459A9661a08c3Fe48d4374D0b61c6;

    address opos1 = 0x3a345EE3F9AC3fD155dD6818273853BEfF2BC645;
    address opos2 = 0x003329939E1Ab600Ada512b37a518145f611E1a0;

    constructor() public {
        depositComplete = false;
    }

    function setHeads(bytes32 x1, bytes32 x2, bytes32 x3, bytes32 x4, bytes32 x5, bytes32 x6, bytes32 x7) public {
        if(msg.sender == merchant_address) {
            h1 = x1;
            h2 = x2;
            h3 = x3;
            h4 = x4;
            h5 = x5;
            h6 = x6;
            h7 = x7;
        }
    }

    function setRevealedHeads(bytes32 x1, bytes32 x2, bytes32 x3, bytes32 x4, bytes32 x5, bytes32 x6, bytes32 x7) private {
        rh1 = x1;
        rh2 = x2;
        rh3 = x3;
        rh4 = x4;
        rh5 = x5;
        rh6 = x6;
        rh7 = x7;
    }

    function getNsigs() public view returns (uint) {
        return nsigs;
    }

    function getNormalizedPriceBase() public view returns (uint) {
        return normalizedPriceBase;
    }

    function getSig0Ready() public view returns (bool) {
        return sig0ready;
    }

    function getSig1Ready() public view returns (bool) {
        return sig1ready;
    }

    function getSig2Ready() public view returns (bool) {
        return sig2ready;
    }

    function getSig3Ready() public view returns (bool) {
        return sig3ready;
    }

    function getSig4Ready() public view returns (bool) {
        return sig4ready;
    }

    function getSig5Ready() public view returns (bool) {
        return sig5ready;
    }

    function getSig6Ready() public view returns (bool) {
        return sig6ready;
    }

    function getSig7Ready() public view returns (bool) {
        return sig7ready;
    }

    function getSig8Ready() public view returns (bool) {
        return sig8ready;
    }

    function getSig9Ready() public view returns (bool) {
        return sig9ready;
    }

    function getSig0() public view returns (bytes memory) {
        return sig0;
    }

    function getSig1() public view returns (bytes memory) {
        return sig1;
    }

    function getSig2() public view returns (bytes memory) {
        return sig2;
    }

    function getSig3() public view returns (bytes memory) {
        return sig3;
    }

    function getSig4() public view returns (bytes memory) {
        return sig4;
    }

    function getSig5() public view returns (bytes memory) {
        return sig5;
    }

    function getSig6() public view returns (bytes memory) {
        return sig6;
    }

    function getSig7() public view returns (bytes memory) {
        return sig7;
    }

    function getSig8() public view returns (bytes memory) {
        return sig8;
    }

    function getSig9() public view returns (bytes memory) {
        return sig9;
    }

    function setSig0(bytes memory x) public {
        require(msg.sender == bro0);
        sig0 = x;
        sig0ready = true;
        nsigs++;
    }

    function setSig1(bytes memory x) public {
        require(msg.sender == bro1);
        sig1 = x;
        sig1ready = true;
        nsigs++;
    }

    function setSig2(bytes memory x) public {
        require(msg.sender == bro2);
        sig2 = x;
        sig2ready = true;
        nsigs++;
    }

    function setSig3(bytes memory x) public {
        require(msg.sender == bro3);
        sig3 = x;
        sig3ready = true;
        nsigs++;
    }

    function setSig4(bytes memory x) public {
        require(msg.sender == bro4);
        sig4 = x;
        sig4ready = true;
        nsigs++;
    }

    function setSig5(bytes memory x) public {
        require(msg.sender == bro5);
        sig5 = x;
        sig5ready = true;
        nsigs++;
    }

    function setSig6(bytes memory x) public {
        require(msg.sender == bro6);
        sig6 = x;
        sig6ready = true;
        nsigs++;
    }

    function setSig7(bytes memory x) public {
        require(msg.sender == bro7);
        sig7 = x;
        sig7ready = true;
        nsigs++;
    }

    function setSig8(bytes memory x) public {
        require(msg.sender == bro8);
        sig8 = x;
        sig8ready = true;
        nsigs++;
    }

    function setSig9(bytes memory x) public {
        require(msg.sender == bro9);
        sig9 = x;
        sig9ready = true;
        nsigs++;
    }

    function getClientAddress() public view returns (address) {
        return client_address;
    }

    function getBro0() public view returns (address) {
        return bro0;
    }

    function getBro1() public view returns (address) {
        return bro1;
    }

    function getBro2() public view returns (address) {
        return bro2;
    }

    function getBro3() public view returns (address) {
        return bro3;
    }

    function getBro4() public view returns (address) {
        return bro4;
    }

    function getBro5() public view returns (address) {
        return bro5;
    }

    function getBro6() public view returns (address) {
        return bro6;
    }

    function getBro7() public view returns (address) {
        return bro7;
    }

    function getBro8() public view returns (address) {
        return bro8;
    }

    function getBro9() public view returns (address) {
        return bro9;
    }

    function getH1() public view returns (bytes32) {
        return h1;
    }

    function getH2() public view returns (bytes32) {
        return h2;
    }

    function getH3() public view returns (bytes32) {
        return h3;
    }

    function getH4() public view returns (bytes32) {
        return h4;
    }

    function getH5() public view returns (bytes32) {
        return h5;
    }

    function getH6() public view returns (bytes32) {
        return h6;
    }

    function getH7() public view returns (bytes32) {
        return h7;
    }

    function getRH1() public view returns (bytes32) {
        return rh1;
    }

    function getRH2() public view returns (bytes32) {
        return rh2;
    }

    function getRH3() public view returns (bytes32) {
        return rh3;
    }

    function getRH4() public view returns (bytes32) {
        return rh4;
    }

    function getRH5() public view returns (bytes32) {
        return rh5;
    }

    function getRH6() public view returns (bytes32) {
        return rh6;
    }

    function getRH7() public view returns (bytes32) {
        return rh7;
    }

    function verify(bytes32 s1, bytes32 s2, bytes32 s3, bytes32 s4, bytes32 s5, bytes32 s6, bytes32 s7, uint k) public view returns (bool) {
        return nest(s1, (k % 10000000) / 1000000) == h1 && nest(s2, (k % 1000000) / 100000) == h2
        && nest(s3, (k % 100000) / 10000) == h3 && nest(s4, (k % 10000) / 1000) == h4
        && nest(s5, (k % 1000) / 100) == h5 && nest(s6, (k % 100) / 10) == h6 && nest(s7, (k % 10) / 1) == h7;
    }

    function nest(bytes32 s, uint k) public pure returns (bytes32) {
        bytes32 roundHash = keccak256(abi.encodePacked(s));

        for(uint8 i = 0; i < k; i++) {
            roundHash = keccak256(abi.encodePacked(roundHash));
        }

        return roundHash;
    }

    event TokenRequestEvent(
        uint k,
        bytes t
    );


    function splitSignature(bytes memory sig)
    internal
    pure
    returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(sig.length == 65);

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function recoverSigner(bytes32 message, bytes memory sig)
    public
    pure
    returns (address)
    {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);

        return ecrecover(message, v, r, s);
    }

    function requestToken(bytes32 s1, bytes32 s2, bytes32 s3, bytes32 s4, bytes32 s5, bytes32 s6, bytes32 s7, uint k, bytes memory t, bytes memory st) public payable {
        require(msg.sender == client_address);

        nsigs = 0;
        sig0ready = false;
        sig1ready = false;
        sig2ready = false;
        sig3ready = false;
        sig4ready = false;
        sig5ready = false;
        sig6ready = false;
        sig7ready = false;
        sig8ready = false;
        sig9ready = false;

        address signer = recoverSigner(keccak256(abi.encodePacked(t)), st);
        require(signer == opos1 || signer == opos2);

        if( nest(s1, ((k+normalizedPriceBase) % 10000000) / 1000000) == h1 &&
        nest(s2, ((k+normalizedPriceBase) % 1000000) / 100000) == h2 &&
        nest(s3, ((k+normalizedPriceBase) % 100000) / 10000) == h3 &&
        nest(s4, ((k+normalizedPriceBase) % 10000) / 1000) == h4 &&
        nest(s5, ((k+normalizedPriceBase) % 1000) / 100) == h5 &&
        nest(s6, ((k+normalizedPriceBase) % 100) / 10) == h6 &&
        nest(s7, ((k+normalizedPriceBase) % 10) / 1) == h7 ) {
            if(address(this).balance >= k * 10000000000000) {
                bro0.transfer(k * 1000000000000);
                bro1.transfer(k * 1000000000000);
                bro2.transfer(k * 1000000000000);
                bro3.transfer(k * 1000000000000);
                bro4.transfer(k * 1000000000000);
                bro5.transfer(k * 1000000000000);
                bro6.transfer(k * 1000000000000);
                bro7.transfer(k * 1000000000000);
                bro8.transfer(k * 1000000000000);
                bro9.transfer(k * 1000000000000);
                normalizedPriceBase += k;
                setRevealedHeads(s1, s2, s3, s4, s5, s6, s7);
                emit TokenRequestEvent(k, t);
            }
        }
    }

    function refund(uint amount) public payable {
        require(msg.sender == merchant_address);
        client_address.transfer(amount);
    }

    function() payable external {
        require(depositComplete == false);
        depositComplete = true;
    }
}
