"use strict";

const crypto = require("crypto");

module.exports.templateTags = [
    {
        name: "hmac",
        displayName: "HMAC",
        description: "Apply HMAC to a value",
        args: [
            {
                displayName: "Algorithm",
                type: "enum",
                options: [
                    { displayName: "MD5", value: "md5" },
                    { displayName: "SHA1", value: "sha1" },
                    { displayName: "SHA256", value: "sha256" },
                    { displayName: "SHA512", value: "sha512" },
                ],
            },
            {
                displayName: "Digest Encoding",
                description: "The encoding of the output",
                type: "enum",
                options: [
                    { displayName: "Hexadecimal", value: "hex" },
                    { displayName: "Latin", value: "latin1" },
                    { displayName: "Base64", value: "base64" },
                ],
            },
            {
                displayName: "Key",
                type: "string",
                placeholder: "HMAC Secret Key",
            },
            {
                displayName: "Identifier",
                type: "string",
                placeholder: "HMAC Prefix",
            },
            {
                displayName: "bearer",
                type: "string",
                placeholder: "Optional Credential value",
            },
        ],
        async run(
            context,
            algorithm,
            encoding,
            key = "",
            identifier = "",
            bearer = undefined
        ) {
            const { meta } = context;
            if (
                encoding !== "hex" &&
                encoding !== "latin1" &&
                encoding !== "base64"
            ) {
                throw new Error(
                    `Invalid encoding ${encoding}. Choices are hex, latin1, base64`
                );
            }

            const hmac = crypto.createHmac(algorithm, key);
            // console.log('bearer', bearer);

            const time = Date.now().toString();
            // const time = '1585068666450';
            // console.log('time', time);
            hmac.update(time);
            const request = await context.util.models.request.getById(
                meta.requestId
            );
            const url = await context.util.render(request.url);
            // console.log('request', url, request);
            const httpMethod = request.method;
            hmac.update(httpMethod);
            // console.log('httpMethod', httpMethod);

            // Regex source : https://tools.ietf.org/html/rfc3986#appendix-B
            const match = url.match(
                /^(([^:\/?#]+):)?(\/\/([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/
            );
            let uri = match[5];
            if (typeof match[6] === "string") {
                uri += match[6];
            }
            
            const encodedURI = encodeURI(uri)            
            hmac.update(encodedURI);
            // console.log('uri', match, uri);
            // console.log('encodedURI', encodedURI);

            const body = request.body.text;
            // console.log('body', body);
            if (body) {
                const realBody = await context.util.render(body);
                // console.log('realBody', realBody);
                const contentHash = crypto.createHash("md5");
                const bodyString = JSON.stringify(JSON.parse(realBody));
                contentHash.update(bodyString);
                const bodyDigest = contentHash.digest(encoding).replace(/\s+/g,'')
                hmac.update(bodyDigest);
                // console.log('bodyString', bodyString);
                // console.log('bodyDigest', bodyDigest);
            }
            const result = hmac.digest(encoding);
            // console.log('result', encoding , result);
            return `${identifier}-${algorithm.toUpperCase()} ${
                bearer ? `Bearer ${bearer} ` : ""
            }Signature=${time}:${result}`;
        },
    },
];
