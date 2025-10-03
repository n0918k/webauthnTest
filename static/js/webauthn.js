function bufferToBase64URLString(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  bytes.forEach((b) => (str += String.fromCharCode(b)));
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64URLStringToBuffer(base64URLString) {
  const padding = '='.repeat((4 - (base64URLString.length % 4)) % 4);
  const base64 = (base64URLString + padding).replace(/-/g, '+').replace(/_/g, '/');
  const str = atob(base64);
  const buffer = new ArrayBuffer(str.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < str.length; i += 1) {
    view[i] = str.charCodeAt(i);
  }
  return buffer;
}

function transformCreateOptions(options) {
  const publicKey = options.publicKey || options;
  publicKey.challenge = base64URLStringToBuffer(publicKey.challenge);
  publicKey.user.id = base64URLStringToBuffer(publicKey.user.id);
  if (publicKey.excludeCredentials) {
    publicKey.excludeCredentials = publicKey.excludeCredentials.map((cred) => ({
      ...cred,
      id: base64URLStringToBuffer(cred.id),
    }));
  }
  return { publicKey };
}

function transformRequestOptions(options) {
  const publicKey = options.publicKey || options;
  publicKey.challenge = base64URLStringToBuffer(publicKey.challenge);
  if (publicKey.allowCredentials) {
    publicKey.allowCredentials = publicKey.allowCredentials.map((cred) => ({
      ...cred,
      id: base64URLStringToBuffer(cred.id),
    }));
  }
  return { publicKey };
}

function serializeRegistration(credential) {
  const transports = credential.response.getTransports ? credential.response.getTransports() : [];
  return {
    id: credential.id,
    rawId: bufferToBase64URLString(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64URLString(credential.response.attestationObject),
      clientDataJSON: bufferToBase64URLString(credential.response.clientDataJSON),
      transports,
    },
  };
}

function serializeAuthentication(assertion) {
  return {
    id: assertion.id,
    rawId: bufferToBase64URLString(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferToBase64URLString(assertion.response.authenticatorData),
      clientDataJSON: bufferToBase64URLString(assertion.response.clientDataJSON),
      signature: bufferToBase64URLString(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? bufferToBase64URLString(assertion.response.userHandle)
        : null,
    },
  };
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });

  const contentType = response.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');
  const payload = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const message =
      (isJson && payload && typeof payload === 'object' && payload.error) ||
      `Request failed with status ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.responseData = payload;
    throw error;
  }

  return payload;
}

window.transformCreateOptions = transformCreateOptions;
window.transformRequestOptions = transformRequestOptions;
window.serializeRegistration = serializeRegistration;
window.serializeAuthentication = serializeAuthentication;
window.postJson = postJson;
