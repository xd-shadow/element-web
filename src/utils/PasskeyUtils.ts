//Copyright

export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const buffer = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    buffer[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return buffer.buffer;
}

export function toBase64Url(input: ArrayBuffer): string {
  let base64 = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(input))))
  // 将 Base64 编码转换为 Base64 URL 编码
  base64 = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return base64;
}
export function parsePublicKeyPoints(spkiBuffer: ArrayBuffer): { x: ArrayBuffer; y: ArrayBuffer, xy: ArrayBuffer } {
  const bytes = new Uint8Array(spkiBuffer);
  // 获取最后64字节的数据
  const PUBKEY_LENGTH = 64;
  const pubKeyBytes = bytes.slice(-PUBKEY_LENGTH);

  return {
    x: pubKeyBytes.slice(0, 32).buffer, // 前32字节为x坐标
    y: pubKeyBytes.slice(32).buffer, // 后32字节为y坐标
    xy: pubKeyBytes.buffer,
  };
}



export default class PasskeyUtils {

  private static genLoginChallenge(username: string): ArrayBuffer {
    return this.genChallenge(username, "Login");
  }

  private static genRegisterChallenge(user: string): ArrayBuffer {
    return this.genChallenge(user, "Register")
  }

  private static genChallenge(user: string, prefix: string): ArrayBuffer {
    const timestampInSeconds = Math.floor(Date.now() / 1000);
    const challenge = `${prefix} ${user}.ont.im at ${timestampInSeconds}`
    return (new TextEncoder).encode(challenge).buffer
  }

  public static async registerWithPasskey(name: string): Promise<string> {
    try {

      const userIdArray = new TextEncoder().encode(name);
      // const challenge = crypto.getRandomValues(new Uint8Array(32));

      const publicKeyCredentialCreationOptions = {
        challenge: this.genRegisterChallenge(name),
        //TODO
        rp: {
          name: "PassKey Demo",
          id: "localhost",
        },
        user: {
          id: userIdArray,
          name: name,
          displayName: name,
        },
        pubKeyCredParams: [
          {
            type: "public-key",
            alg: -7, // ES256
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "required",
        },
        timeout: 60000,
      };

      const credential = (await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions as any,
      })) as PublicKeyCredential;
      console.log('credential', credential);
      const response = credential.response as AuthenticatorAttestationResponse;
      //TODO 临时
      const publicKey = response.getPublicKey();
      if (!publicKey) {
        throw new Error("Failed to get public key");
      }
      const { xy } = parsePublicKeyPoints(publicKey);
      const publicKeyBase64Url = toBase64Url(xy);
      console.log('publicKeyBase64Url', publicKeyBase64Url);

      const password = JSON.stringify(
        {
          attestation: {
            type: credential.type,
            rawId: toBase64Url(credential.rawId),
            id: credential.id,
            response: {
              attestationObject: toBase64Url(response.attestationObject),
              clientDataJSON: toBase64Url(response.clientDataJSON),
            }
          }
        }
      )
      return password;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (error) {
      throw new Error("Failed to register passkey");
    }
  };
  public static async loginWithPasskey(name: string): Promise<string> {
    try {
      const publicKeyCredentialRequestOptions = {
        challenge: this.genLoginChallenge(name),
        rpId: "localhost",
        timeout: 60000,
        userVerification: "required",
      };

      const credential = (await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions as any,
      })) as PublicKeyCredential;

      const response = credential.response as AuthenticatorAssertionResponse;
      console.log('credential', credential);

      const password = JSON.stringify(
        {
          publicKey: '3YLDOf07qeY1QTYOdX7L5nF2Rpuq_bLAmFDDqou0QaWnwm93JbL9HTBJXBwtGJ1w80SjUV_Tc9PcZ1_NRswErw',
          assertion: {
            type: credential.type,
            rawId: toBase64Url(credential.rawId),
            id: credential.id,
            response: {
              authenticatorData: toBase64Url(response.authenticatorData),
              clientDataJSON: toBase64Url(response.clientDataJSON),
              signature: toBase64Url(response.signature),
            }
          }
        }
      )
      return password;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (error: any) {
      console.error(error)
      throw new Error("Failed to login passkey");
    }
  }
  // private static verifySignature = async (signature: ArrayBuffer, publicKey: CryptoKey, data: ArrayBuffer): Promise<boolean> => {

  // }
}