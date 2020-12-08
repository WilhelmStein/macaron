# Macaron Explorer

A transaction trace exploration tool for contracts written in Solidity, on the Ethereum blockchain.

## Description
This is a tool which upon being supplied with a transaction hash, the solidity contract code relevant to said transaction (through a mysql database such as [contract-library](https://contract-library.com)), and an ethereum node ip, takes the EVM trace dump of the transaction and maps it to the source code. This way, the contract path of execution and state changes can be viewed in a more user-friendly way.

## Installation
Run setup.sh