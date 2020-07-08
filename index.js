// Create temporary AWS credentials using SAML provider.

const AWS = require('aws-sdk');
const sts = new AWS.STS();
const request = require('request').defaults({ jar: true });
const url = require('url');
const JSSoup = require('jssoup').default;
const path = require('path');
const fs = require('fs');
const ini = require('ini');

const HOME = process.env.HOME || process.env.HOMEPATH;
const CONFIG_FILE = path.join(HOME, '.aws', 'credentials');

let IDP_URL = process.env.IDP_URL;
let IDP_USER = process.env.IDP_USER;
let IDP_PASS = process.env.IDP_PASS;
let AWS_PROFILE = process.env.AWS_PROFILE;

function base64encode(data) {
    return Buffer.from(data, 'utf8').toString('base64');
}

function base64decode(data) {
    return Buffer.from(data, 'base64').toString('utf8');
}

function httpGet(url) {
    const options = {
        url,
    };
    return new Promise((resolve, reject) => {
        request.get(options, (error, response, body) => {
            if (error) {
                reject(error);
            } else {
                resolve({ response, body });
            }
        });
    });
}

function httpPost(url, form) {
    const options = {
        url,
        form,
        followAllRedirects: true,
    };
    return new Promise((resolve, reject) => {
        request.post(options, (error, response, body) => {
            if (error) {
                reject(error);
            } else {
                resolve({ response, body });
            }
        });
    });
}

function getLoginData(body) {
    const soup = new JSSoup(body);
    const forms = soup.findAll('form');
    const form = forms.find((form) => form.attrs.id === 'loginForm');

    if (!form) {
        throw new Error('LOGIN_FORM_NOT_FOUND');
    }

    const action = url.resolve(IDP_URL, form.attrs.action);
    const inputs = {};

    for (const input of form.findAll('input')) {
        const name = input.attrs.name || '';
        const value = input.attrs.value || '';
        const namelc = name.toLowerCase();

        if (namelc.includes('user')) {
            inputs[name] = IDP_USER;
        } else if (namelc.includes('email')) {
            inputs[name] = IDP_USER;
        } else if (namelc.includes('pass')) {
            inputs[name] = IDP_PASS;
        } else {
            inputs[name] = value;
        }
    }

    return { action, inputs };
}

function getSAMLAssertion(body) {
    const soup = new JSSoup(body);
    const inputs = soup.findAll('input');
    const saml = inputs.find((input) => input.attrs.name === 'SAMLResponse');

    if (!saml) {
        throw new Error('SAML_ASSERTION_NOT_FOUND');
    }

    return base64decode(saml.attrs.value);
}

function getSAMLRoles(saml) {
    const soup = new JSSoup(saml);
    const roles = soup
        .findAll('AttributeValue')
        .filter((value) => {
            return (
                value.parent &&
                value.parent.name === 'Attribute' &&
                value.parent.attrs &&
                value.parent.attrs.Name ===
                    'https://aws.amazon.com/SAML/Attributes/Role'
            );
        })
        .map((value) => {
            const [provider, role] = (value.text || '').split(',');
            return { provider, role };
        });

    if (!roles[0]) {
        throw new Error('SAML_ROLE_NOT_FOUND');
    }

    return roles;
}

async function getSTSToken(provider, role, assertion) {
    const params = {
        DurationSeconds: 3600,
        PrincipalArn: provider,
        RoleArn: role,
        SAMLAssertion: base64encode(assertion),
    };
    return new Promise((resolve, reject) => {
        sts.assumeRoleWithSAML(params, (error, data) => {
            if (error) {
                reject(error);
            } else {
                resolve(data);
            }
        });
    });
}

function saveSTSToken(filename, profile, sts) {
    const readFile = () => {
        try {
            return ini.decode(fs.readFileSync(filename, 'utf-8'));
        } catch (e) {
            return {};
        }
    };

    const writeFile = (config) => {
        fs.writeFileSync(filename, ini.encode(config, { whitespace: true }));
    };

    const config = readFile();
    const section = config[profile] || {};
    const credentials = sts.Credentials || {};

    section.aws_access_key_id = credentials.AccessKeyId;
    section.aws_secret_access_key = credentials.SecretAccessKey;
    section.aws_session_token = credentials.SessionToken;

    config[profile] = section;
    writeFile(config);
}

function checkUsage() {
    if (!IDP_URL) {
        throw new Error('IDP_URL not set!');
    }
    if (!IDP_USER) {
        throw new Error('IDP_USER not set!');
    }
    if (!IDP_PASS) {
        throw new Error('IDP_PASS not set!');
    }
    if (!AWS_PROFILE) {
        throw new Error('AWS_PROFILE not set!');
    }
}

(async function main() {
    try {
        console.log(`aws-saml-session started.`);
        checkUsage();

        console.log(`Logging into SAML provider...`);
        const resp1 = await httpGet(IDP_URL);
        const data = getLoginData(resp1.body);

        const resp2 = await httpPost(data.action, data.inputs);
        const saml = getSAMLAssertion(resp2.body);

        const roles = getSAMLRoles(saml);

        const { provider, role } = roles[0];

        console.log(`Assuming role: ${role}...`);
        const sts = await getSTSToken(provider, role, saml);

        console.log(`Saving credentials: ${AWS_PROFILE}...`);
        saveSTSToken(CONFIG_FILE, AWS_PROFILE, sts);

        console.log('Done.');
    } catch (e) {
        console.log('ERROR:', e.message);
    }
})();
