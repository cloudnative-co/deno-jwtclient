import { importPKCS8, SignJWT } from "https://deno.land/x/jose@v4.6.0/index.ts";
import { v5 } from "https://deno.land/std@0.165.0/uuid/mod.ts";

export interface Payload {
  iss?: string;
  sub?: string;
  aud?: string[] | string;
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}
interface TokenPayload {
  [key: string]: unknown;
}


export class JWTClient {
    access_token: string = "";
    expires_in: number = 0;
    token_type: string = "";

    async getJson(filePath: string) {
        try {
            return JSON.parse(await Deno.readTextFile(filePath));
        } catch(e) {
            console.log(filePath+': '+e.message);
        }
    }

    protected async sign(payload: Payload, alg: string, key: string) {
        const jwt = await new SignJWT(payload).setProtectedHeader({ alg: alg });
        return jwt.sign(await importPKCS8(key, alg));
    }

    protected async request_token(url: string, assertion: string, options?: any) {
        var dt: TokenPayload = {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion: assertion
        }
        if (options !== null){
            dt = Object.assign(dt, options);
        }
        var aryBody = [];
        for (const prop in dt) {
            aryBody.push(`${prop}=${dt[prop]}`)
        }
        const body: string = aryBody.join("&");
        var res = await fetch(url, {
            method: "POST",
            body: body,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
        });
        var data = await res.json();
        this.access_token = data.access_token;
        this.expires_in = data.expires_in;
        this.token_type = data.token_type;
        return data;
    }
}
