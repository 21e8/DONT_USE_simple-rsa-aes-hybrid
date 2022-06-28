import * as cryptico from 'cryptico-js/dist/cryptico.browser.js';

import { RSAKey } from '@mpe/common';

/**
 * This class is responsible for generating RSA keys from a passphrase (Super PIN)
 * https://github.com/phpmycoder/cryptico-node
 */
export class RSA {
  bits: number;

  constructor(bits?: number) {
    this.bits = bits || 1024;
  }

  generateKey(passphrase: string) {
    return cryptico.generateRSAKey(passphrase, this.bits);
  }

  encrypt(message: string, receiverPublicKey: string, senderKey?: RSAKey) {
    return cryptico.encrypt(message, receiverPublicKey, senderKey);
  }

  publicKeyID(publicKey: string) {
    return cryptico.publicKeyID(publicKey);
  }

  decrypt(message: string, privateKey: RSAKey) {
    return cryptico.decrypt(message, privateKey);
  }

  publicKeyString(key: RSAKey) {
    return cryptico.publicKeyString(key);
  }
}
