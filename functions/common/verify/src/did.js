// import axios from 'axios';

/**
 * Returns well-known keys
 * @return {Object} did document
 */
function getDidDoc() {
  // const url = 'https://nzcp.identity.health.nz/.well-known/did.json';
  // const response = await axios.get(url)
  // return response.data;
  return {
    "id": "did:web:nzcp.identity.health.nz",
    "@context": [
      "https://w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    "verificationMethod": [
      {
        "id": "did:web:nzcp.identity.health.nz#z12Kf7UQ",
        "controller": "did:web:nzcp.identity.health.nz",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "DQCKJusqMsT0u7CjpmhjVGkHln3A3fS-ayeH4Nu52tc",
          "y": "lxgWzsLtVI8fqZmTPPo9nZ-kzGs7w7XO8-rUU68OxmI",
        },
      },
    ],
    "assertionMethod": [
      "did:web:nzcp.identity.health.nz#z12Kf7UQ",
    ],
  };
}

module.exports.getDidDoc = getDidDoc;
