import {
  DecryptionResult,
  EncyrptionResult,
  RSAKey,
  TransportedMessage,
  TransportMessage,
} from '/types/i/do/not/have/right/now/but/also/dont/really/matter';
import { AES } from './aes';
import { RSA } from './rsa';
import { arrayBufferToString, stringToArrayBuffer } from './util';

export class EncryptionService {
  private readonly rsa = new RSA();
  private readonly aes = new AES();

  generateRsaKey(passphrase: string): RSAKey {
    return this.rsa.generateKey(passphrase);
  }

  publicKeyString(key: RSAKey): string {
    return this.rsa.publicKeyString(key);
  }

  async generateTransportMessage(
    payload: string,
    key: RSAKey
  ): Promise<TransportMessage> {
    const iv = this.aes.getIv();
    const transportKey = await this.aes.generateKey();
    const exportedKey = await this.aes.exportKey(transportKey);
    const encPayload = await this.aes.encrypt(payload, transportKey, iv);
    const { cipher }: EncyrptionResult = this.rsa.encrypt(
      exportedKey,
      this.publicKeyString(key)
    );
    return {
      encryptedPayload: arrayBufferToString(encPayload),
      transportKey: cipher,
      iv: arrayBufferToString(iv),
    };
  }

  async decryptTransportMessage(
    transportedMessage: TransportedMessage,
    key: RSAKey
  ): Promise<string> {
    const { plaintext }: DecryptionResult = await this.rsa.decrypt(
      transportedMessage.transportKey,
      key
    );

    const decTransportKey = JSON.parse(plaintext);

    const importedDecTransportKey = await this.aes.importKey(decTransportKey);

    return await this.aes.decrypt(
      transportedMessage.encryptedPayload,
      importedDecTransportKey,
      transportedMessage.iv
    );
  }

  parseTransportMessage(
    transportMessage: TransportMessage
  ): TransportedMessage {
    return {
      encryptedPayload: stringToArrayBuffer(transportMessage.encryptedPayload),
      transportKey: transportMessage.transportKey,
      iv: stringToArrayBuffer(transportMessage.iv),
    };
  }
}
