import { arrayBufferToString, stringToArrayBuffer } from './util';

const name = 'AES-GCM';
const keyType = 'jwk';
const length = 256;
const modes: KeyUsage[] = ['encrypt', 'decrypt'];

/**
 * This class is resposible for generating transport keys.
 * These are symmetric keys which will be encrypted with RSA and sent along with the message itself.
 */
export class AES {
  async encrypt(
    plaintext: string,
    key: CryptoKey,
    iv: Uint8Array
  ): Promise<ArrayBuffer> {
    return await window.crypto.subtle.encrypt(
      {
        name: name,
        iv: iv,
      },
      key,
      stringToArrayBuffer(plaintext)
    );
  }

  getIv(): Uint8Array {
    return window.crypto.getRandomValues(new Uint8Array(16));
  }

  async decrypt(
    cipher: ArrayBuffer,
    key: CryptoKey,
    iv: ArrayBufferLike
  ): Promise<string> {
    const result = await window.crypto.subtle.decrypt(
      {
        name: name,
        iv: iv,
      },
      key,
      cipher
    );
    return arrayBufferToString(result);
  }

  async importKey(key: JsonWebKey): Promise<CryptoKey> {
    return await window.crypto.subtle.importKey(
      keyType,
      key,
      {
        name: name,
        length: length,
      },
      true,
      modes
    );
  }

  async exportKey(key: CryptoKey): Promise<string> {
    return JSON.stringify(await window.crypto.subtle.exportKey(keyType, key));
  }

  async generateKey(): Promise<CryptoKey> {
    return await window.crypto.subtle.generateKey(
      {
        name: name,
        length: length,
      },
      true,
      modes
    );
  }
}
