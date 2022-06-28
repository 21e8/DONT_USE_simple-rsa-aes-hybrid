export function arrayBufferToString(buffer: ArrayBufferLike): string {
  return String.fromCharCode(...new Uint8Array(buffer));
}

export function stringToArrayBuffer(str: string): ArrayBufferLike {
  return Uint8Array.from([...str].map((ch) => ch.charCodeAt(0)));
}
