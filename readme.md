# Macaron Explorer

A transaction trace exploration tool for contracts written in Solidity, on the Ethereum blockchain.

## Description
This is a tool which upon being supplied with a transaction hash, the solidity contract code relevant to said transaction (through a mysql database such as [contract-library](https://contract-library.com)), and an ethereum node ip, takes the EVM trace dump of the transaction and maps it to the source code. This way, the contract path of execution and state changes can be viewed in a more user-friendly way.

## Installation
Run setup.sh

## Usage

After running the setup.sh file, make sure you have an established connection (e.g. ssh tunneling) to a mysql database that contains the contract source code and to an ethereum node that has the **debug_traceTransaction** rpc call enabled (e.g. geth).

Navigate to the project root directory and run `. ./env/activate`. Now the virtual python environment has been activated.

Run `python macaron_shell.py -h` to see which arguments much be supplied.