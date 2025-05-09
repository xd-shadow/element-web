// # Copyright 2024 New Vector Ltd.
import { MatrixClient, Method } from "matrix-js-sdk/src/matrix";

interface IPasskeyCredential {
  id: string;
  publicKey: string;
}

declare module "matrix-js-sdk/src/client" {
  interface MatrixClient {
    getPasskeyCredentials(userId: string): Promise<IPasskeyCredential[]>;
  }
}

const registerExtendApis = function (): void {
  MatrixClient.prototype.getPasskeyCredentials = function (
    userId: string
  ): Promise<IPasskeyCredential[]> {
    return this.http.authedRequest(
      Method.Get,
      `/profile/${encodeURIComponent(userId)}/credentials`,
      undefined, // query params
      undefined, // data
      { prefix: "/_matrix/client/v3" }
    );
  };
}
registerExtendApis()