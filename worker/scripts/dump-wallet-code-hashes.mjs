import { Buffer } from 'node:buffer';
import {
  WalletContractV1R1, WalletContractV1R2, WalletContractV1R3,
  WalletContractV2R1, WalletContractV2R2, WalletContractV3R1,
  WalletContractV3R2, WalletContractV4, WalletContractV5R1
} from '@ton/ton';

const contracts = {
  v1r1: WalletContractV1R1,
  v1r2: WalletContractV1R2,
  v1r3: WalletContractV1R3,
  v2r1: WalletContractV2R1,
  v2r2: WalletContractV2R2,
  v3r1: WalletContractV3R1,
  v3r2: WalletContractV3R2,
  v4r2: WalletContractV4,
  v5r1: WalletContractV5R1
};
const hashes = {};
for (const [name, contract] of Object.entries(contracts)) {
  hashes[name] = contract.create({ workchain: 0, publicKey: Buffer.alloc(32) }).init.code.hash().toString('hex');
}
console.log('IFZI_REVIEWED_WALLET_CODE_HASHES=' + JSON.stringify(hashes));
