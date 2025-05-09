// Copyright

import React from "react";
import { logger } from "matrix-js-sdk/src/logger";
import { type AuthDict, createClient, type MatrixClient, MatrixError } from "matrix-js-sdk/src/matrix";

import { type ValidatedServerConfig } from "../../../utils/ValidatedServerConfig";
import { type IMatrixClientCreds } from "../../../MatrixClientPeg";
import Login from "../../../Login";
import PasskeyUtils from "../../../utils/PasskeyUtils";

const username = 'testuser14'

interface IProps {
    onLoginComplete: (credentials: IMatrixClientCreds) => Promise<void>;
    serverConfig: ValidatedServerConfig;
}

interface IState {
    busy: boolean;
    errorText?: string;
    flows: any[] | null;
    doingUIAuth: boolean;

}

export default class PasskeyWelcome extends React.Component<IProps, IState> {
    private loginLogic: Login;
    private matrixClient: MatrixClient;

    public constructor(props: IProps) {
        super(props);

        this.state = {
            busy: false,
            flows: null,
            doingUIAuth: false,

        };

        this.loginLogic = new Login(props.serverConfig.hsUrl, props.serverConfig.isUrl, null, {
            defaultDeviceDisplayName: "My_Device",
        });

        this.matrixClient = createClient({
            baseUrl: this.props.serverConfig.hsUrl,
        });
    }

    private makeRegisterRequest = async (auth: AuthDict | null, username: string, password: string): Promise<any> => {
        // 构造注册请求参数
        const registerParams = {
            username: username,
            password: password,
            initial_device_display_name: "My_Device",
            auth: auth && auth || undefined,
        };

        return this.matrixClient.registerRequest(registerParams);


    };

    private handlePasskeyRegister = async (): Promise<void> => {
        try {
            this.setState({ busy: true, errorText: undefined });

            const password = await PasskeyUtils.registerWithPasskey(username);
            let session: string | null = null

            // 2. 首次调用注册接口获取 session
            try {
                const res = await this.makeRegisterRequest(null, username, password);
                console.log("makeRegisterRequest", res);

            } catch (e: any) {
                console.log('error', JSON.stringify(e));
                console.log('e.httpStatus', e.httpStatus);

                if (e instanceof MatrixError && e.httpStatus === 401) {
                    console.log('e.data.session', e.data.session);
                    session = e.data.session;
                    // 保存 session 信息
                    this.setState({
                        flows: e.data.flows,
                    });
                } else {
                    throw e;
                }
            }

            // 3. 使用 session 进行认证注册
            console.log('this.state', this.state);

            const response = await this.makeRegisterRequest({
                type: "m.login.dummy",
                session: session,
            }, username, password);

            // 4. 注册成功,获取凭证
            const credentials: IMatrixClientCreds = {
                userId: response.user_id,
                deviceId: response.device_id,
                accessToken: response.access_token,
                homeserverUrl: this.props.serverConfig.hsUrl,
                identityServerUrl: this.props.serverConfig.isUrl,
            };

            // 5. 直接登录
            await this.props.onLoginComplete(credentials);

        } catch (error) {
            logger.error("Passkey register failed", error);
            this.setState({
                errorText: "Register error: " + (error instanceof Error ? error.message : String(error)),
            });
        } finally {
            this.setState({ busy: false });
        }
    };


    private handlePasskeyLogin = async (): Promise<void> => {
        try {
            this.setState({ busy: true, errorText: undefined });

            // 1. 获取验证凭证
            const password = await PasskeyUtils.loginWithPasskey(username, this.matrixClient);

            // 2. 使用 password 作为密码登录
            const credentials = await this.loginLogic.loginViaPassword(
                username,
                undefined,
                undefined,
                password
            );

            // 3. 登录成功后进入主界面
            await this.props.onLoginComplete(credentials);

        } catch (error) {
            logger.error("Passkey login failed", error);
            this.setState({
                errorText: "登录失败: " + (error instanceof Error ? error.message : String(error)),
            });
        } finally {
            this.setState({ busy: false });
        }
    };

    public render(): React.ReactNode {
        const { busy, errorText } = this.state;

        return (
            <div className="mx_PasskeyWelcome">
                {errorText && <div className="mx_PasskeyWelcome_error">{errorText}</div>}
                <button onClick={this.handlePasskeyRegister} disabled={busy} className="mx_PasskeyWelcome_button">
                    {busy ? "注册中..." : "注册新Passkey"}
                </button>
                <button onClick={this.handlePasskeyLogin} disabled={busy} className="mx_PasskeyWelcome_button">
                    {busy ? "登录中..." : "使用Passkey登录"}
                </button>
            </div>
        );
    }
}
