const readline = require('readline');
const { Issuer } = require('openid-client');
const { generators } = require('openid-client');
const code_verifier = generators.codeVerifier();

const config = {
  client_id: '',
  client_secret: '',
  redirect_uris: [''],
  resource: '',
  issuer: ''
};


Issuer.discover(config['issuer'])
  .then(function (iss) {

    // console.log('Discovered issuer %s %O', iss.issuer, iss.metadata);

    if (!iss.metadata.jwks_uri) {
      console.error("%O", iss.metadata);
      console.error("No jwks_uri found, bailing");
      return;
    }

    const client = new iss.Client({
      ...config,
      response_types: ['code'],
      // id_token_signed_response_alg (default "RS256")
      // token_endpoint_auth_method (default "client_secret_basic")
    });

    const code_challenge = generators.codeChallenge(code_verifier);

    const state = Math.random().toString(36);
    const url = client.authorizationUrl({
      state,
      scope: 'openid profile',
      resource: config['resource'],
      code_challenge,
      code_challenge_method: 'S256',
    });
    console.log("Open the following url in your browser, and paste you're redirect to here:");
    console.log(url + "\n");

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    rl.question('Redirected url: ', function(respUrl) {
      const params = client.callbackParams(respUrl);
      client.callback(config.redirect_uris[0], params, { code_verifier, state })
        .then(function (tokenSet) {
          console.log('received and validated tokens %j', tokenSet);
          console.log('validated ID Token claims %j', tokenSet.claims());
        });
    });
  });
