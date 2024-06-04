import { WebPlugin } from '@capacitor/core';
import type {
  OAuth2AuthenticateOptions,
  GenericOAuth2Plugin,
  OAuth2RefreshTokenOptions,
} from './definitions';
import type { WebOptions } from './web-utils';
import { WebUtils } from './web-utils';

export class GenericOAuth2Web extends WebPlugin implements GenericOAuth2Plugin {
  private webOptions: WebOptions;
  private windowHandle: Window | null;
  private intervalId: number;
  private loopCount = 2000;
  private intervalLength = 100;
  private windowClosedByPlugin: boolean;

  /**
   * Get a new access token using an existing refresh token.
   */
  async refreshToken(options: OAuth2RefreshTokenOptions): Promise<any> {
    return new Promise<any>((resolve, reject) => {
      if (!options.refreshToken) {
        reject(new Error('ERR_NO_REFRESH_TOKEN'));
        return;
      }
      if (!this.webOptions.accessTokenEndpoint && !options.accessTokenEndpoint) {
        reject(new Error('ERR_NO_ACCESS_TOKEN_ENDPOINT'));
        return;
      }

      const tokenRequest = new XMLHttpRequest();
      tokenRequest.onload = function () {
        if (this.status === 200) {
          const accessTokenResponse = JSON.parse(this.response);
          resolve(accessTokenResponse);
        } else {
          reject(new Error(this.statusText));
        }
      };
      tokenRequest.onerror = function () {
        reject(new Error('ERR_GENERAL'));
      };
      tokenRequest.open('POST', this.webOptions.accessTokenEndpoint || options.accessTokenEndpoint, true);
      //tokenRequest.setRequestHeader('accept', 'application/json');
      //tokenRequest.setRequestHeader('cache-control', 'no-cache');
      tokenRequest.setRequestHeader('content-type', 'application/x-www-form-urlencoded');
      tokenRequest.send(
        WebUtils.getTokenEndpointDataForRefreshToken(
          this.webOptions ?? options,
          options.refreshToken
        )
      );
    });
  }

  async authenticate(options: OAuth2AuthenticateOptions): Promise<any> {
    const windowOptions = WebUtils.buildWindowOptions(options);

    // we open the window first to avoid popups being blocked because of
    // the asynchronous buildWebOptions call
    this.windowHandle = window.open(
      '',
      windowOptions.windowTarget,
      windowOptions.windowOptions,
    );

    this.webOptions = await WebUtils.buildWebOptions(options);
    return new Promise<any>((resolve, reject) => {
      // validate
      if (!this.webOptions.appId || this.webOptions.appId.length == 0) {
        reject(new Error('ERR_PARAM_NO_APP_ID'));
      } else if (
        !this.webOptions.authorizationBaseUrl ||
        this.webOptions.authorizationBaseUrl.length == 0
      ) {
        reject(new Error('ERR_PARAM_NO_AUTHORIZATION_BASE_URL'));
      } else if (
        !this.webOptions.redirectUrl ||
        this.webOptions.redirectUrl.length == 0
      ) {
        reject(new Error('ERR_PARAM_NO_REDIRECT_URL'));
      } else if (
        !this.webOptions.responseType ||
        this.webOptions.responseType.length == 0
      ) {
        reject(new Error('ERR_PARAM_NO_RESPONSE_TYPE'));
      } else {
        // init internal control params
        let loopCount = this.loopCount;
        this.windowClosedByPlugin = false;
        // open window
        const authorizationUrl = WebUtils.getAuthorizationUrl(this.webOptions);
        if (this.webOptions.logsEnabled) {
          this.doLog('Authorization url: ' + authorizationUrl);
        }
        if (this.windowHandle) {
          this.windowHandle.location.href = authorizationUrl;
        }
        // wait for redirect and resolve the
        this.intervalId = window.setInterval(() => {
          if (loopCount-- < 0) {
            this.closeWindow();
          } else if (this.windowHandle?.closed && !this.windowClosedByPlugin) {
            window.clearInterval(this.intervalId);
            reject(new Error('USER_CANCELLED'));
          } else {
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            let href: string = undefined!;
            try {
              // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
              href = this.windowHandle!.location.href!;
            } catch (ignore) {
              // ignore DOMException: Blocked a frame with origin "http://localhost:4200" from accessing a cross-origin frame.
            }

            if (
              href != null &&
              href.indexOf(this.webOptions.redirectUrl) >= 0
            ) {
              if (this.webOptions.logsEnabled) {
                this.doLog('Url from Provider: ' + href);
              }
              const authorizationRedirectUrlParamObj =
                WebUtils.getUrlParams(href);
              if (authorizationRedirectUrlParamObj) {
                if (this.webOptions.logsEnabled) {
                  this.doLog(
                    'Authorization response:',
                    authorizationRedirectUrlParamObj,
                  );
                }
                window.clearInterval(this.intervalId);
                // check state
                if (
                  authorizationRedirectUrlParamObj.state ===
                  this.webOptions.state
                ) {
                  if (this.webOptions.accessTokenEndpoint) {
                    const authorizationCode =
                      authorizationRedirectUrlParamObj.code;
                    
                    if (authorizationCode) {
                      this.exchangeAuthorizationCodeForTokens(
                        authorizationRedirectUrlParamObj.code,
                        this.webOptions.redirectUrl,
                        this.webOptions.appId,
                        this.webOptions.pkceCodeVerifier
                      ).then(tokenResponse => {
                        this.requestResource(tokenResponse.access_token , resolve , reject , authorizationRedirectUrlParamObj , tokenResponse);
                      }).catch(error => {
                        reject(error);
                      });
                      this.closeWindow();
                    } else {
                      reject(new Error('ERR_NO_AUTHORIZATION_CODE'));
                    }
                    this.closeWindow();
                  } else {
                    // if no accessTokenEndpoint exists request the resource
                    this.requestResource(
                      authorizationRedirectUrlParamObj.access_token,
                      resolve,
                      reject,
                      authorizationRedirectUrlParamObj,
                    );
                  }
                } else {
                  if (this.webOptions.logsEnabled) {
                    this.doLog(
                      'State from web options: ' + this.webOptions.state,
                    );
                    this.doLog(
                      'State returned from provider: ' +
                        authorizationRedirectUrlParamObj.state,
                    );
                  }
                  reject(new Error('ERR_STATES_NOT_MATCH'));
                  this.closeWindow();
                }
              }
              // this is no error no else clause required
            }
          }
        }, this.intervalLength);
      }
    });
  }

  private exchangeAuthorizationCodeForTokens(
    code: string,
    redirectUri: string,
    clientId: string,
    codeVerifier: string
  ): Promise<any> {
    const tokenEndpoint = this.webOptions.accessTokenEndpoint;

    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('client_id', clientId);
    params.append('code_verifier', codeVerifier);
    params.append('code', code);
    params.append('redirect_uri', redirectUri);
  

    return new Promise<any>((resolve, reject) => {
      const tokenRequest = new XMLHttpRequest();
      tokenRequest.onload = function () {
        if (this.status === 200) {
          const tokenResponse = JSON.parse(this.response);
          resolve(tokenResponse);
        } else {
          reject(new Error(this.statusText));
        }
      };
      tokenRequest.onerror = function () {
        reject(new Error('ERR_GENERAL'));
      };
      tokenRequest.open('POST', tokenEndpoint, true);
      tokenRequest.setRequestHeader('content-type', 'application/x-www-form-urlencoded');
      tokenRequest.send(params.toString());
    });
  }

  private readonly MSG_RETURNED_TO_JS = 'Returned to JS:';

  private requestResource(
    accessToken: string,
    resolve: any,
    reject: (reason?: any) => void,
    authorizationResponse: any,
    accessTokenResponse: any = null,
  ) {
    if (this.webOptions.resourceUrl) {
      const logsEnabled = this.webOptions.logsEnabled;
      if (logsEnabled) {
        this.doLog('Resource url: ' + this.webOptions.resourceUrl);
      }
      if (accessToken) {
        if (logsEnabled) {
          this.doLog('Access token:', accessToken);
        }
        const self = this;
        const request = new XMLHttpRequest();
        request.onload = function () {
          if (this.status === 200) {
            const resp = JSON.parse(this.response);
            if (logsEnabled) {
              self.doLog('Resource response:', resp);
            }
            if (resp) {
              self.assignResponses(
                resp,
                accessToken,
                authorizationResponse,
                accessTokenResponse,
              );
            }
            if (logsEnabled) {
              self.doLog(self.MSG_RETURNED_TO_JS, resp);
            }
            resolve(resp);
          } else {
            reject(new Error(this.statusText));
          }
          self.closeWindow();
        };
        request.onerror = function () {
          if (logsEnabled) {
            self.doLog('ERR_GENERAL: ' + this.statusText);
          }
          reject(new Error('ERR_GENERAL'));
          self.closeWindow();
        };
        request.open('GET', this.webOptions.resourceUrl, true);
        request.setRequestHeader('Authorization', `Bearer ${accessToken}`);
        if (this.webOptions.additionalResourceHeaders) {
          for (const key in this.webOptions.additionalResourceHeaders) {
            request.setRequestHeader(
              key,
              this.webOptions.additionalResourceHeaders[key],
            );
          }
        }
        request.send();
      } else {
        if (logsEnabled) {
          this.doLog(
            'No accessToken was provided although you configured a resourceUrl. Remove the resourceUrl from the config.',
          );
        }
        reject(new Error('ERR_NO_ACCESS_TOKEN'));
        this.closeWindow();
      }
    } else {
      // if no resource url exists just return the accessToken response
      const resp = {};
      this.assignResponses(
        resp,
        accessToken,
        authorizationResponse,
        accessTokenResponse,
      );
      if (this.webOptions.logsEnabled) {
        this.doLog(this.MSG_RETURNED_TO_JS, resp);
      }
      resolve(resp);
      this.closeWindow();
    }
  }

  assignResponses(
    resp: any,
    accessToken: string,
    authorizationResponse: any,
    accessTokenResponse: any = null,
  ): void {
    // #154
    if (authorizationResponse) {
      resp['authorization_response'] = authorizationResponse;
    }
    if (accessTokenResponse) {
      resp['access_token_response'] = accessTokenResponse;
    }
    resp['access_token'] = accessToken;
  }

  async logout(options: OAuth2AuthenticateOptions): Promise<boolean> {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    return new Promise<any>((resolve, _reject) => {
      localStorage.removeItem(WebUtils.getAppId(options));
      resolve(true);
    });
  }

  private closeWindow() {
    window.clearInterval(this.intervalId);
    // #164 if the provider's login page is opened in the same tab or window it must not be closed
    // if (this.webOptions.windowTarget !== "_self") {
    //     this.windowHandle?.close();
    // }
    this.windowHandle?.close();
    this.windowClosedByPlugin = true;
  }

  private doLog(msg: string, obj: any = null) {
    console.log('I/Capacitor/GenericOAuth2Plugin: ' + msg, obj);
  }
}
