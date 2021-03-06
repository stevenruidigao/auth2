function alertUser(div, type, message, time=5000) {
	let alertDiv = document.createElement('div');
	alertDiv.className = 'alert hidden ' + type;
	p = document.createElement('p');
	p.innerText = message;
	alertDiv.appendChild(p);
	alerts = document.getElementsByClassName('alert');

	for (old of alerts) {
		// old.remove();
	}

	alertDiv.opacity = 0;

	if (alerts.length == 0) {
		div.insertBefore(alertDiv, div.firstChild);

	} else if (alerts.length >= 5) {
		div.firstChild.remove();
		div.firstChild.className = alertDiv.className.replace('hidden ', 'visible ');
		div.insertBefore(alertDiv, alerts[alerts.length - 1].nextSibling);

	} else {
		div.insertBefore(alertDiv, alerts[alerts.length - 1].nextSibling);
	}

	setTimeout(function () {
		alertDiv.className = alertDiv.className.replace('hidden ', 'visible ');
	}, 0);

	setTimeout(function () {
		alertDiv.className = alertDiv.className.replace('visible ', 'hidden ');

		setTimeout(function () {
			alertDiv.remove();
		}, 1000);
	}, time);
}

function focusPassword(event) {
	if (event && event.type !== 'click' && (event.type == 'keydown' && event.code !== 'Enter')) {
		return;
	}

	document.getElementById('password').focus();
}

function goLogin() {
	window.location.href = '/login';
}

function goRegister() {
	window.location.href = '/register';
}

function login(event) {
	if (event && event.type !== 'click' && (event.type == 'keydown' && event.code !== 'Enter')) {
		return;
	}

	username = document.getElementById('username');
	password = document.getElementById('password');
	totp = document.getElementById('totp');

	if (username != null && password != null) {
		request = new XMLHttpRequest();
		request.open('POST', '/api/auth/salt', true);
		request.send(JSON.stringify({'username': username.value}));

		request.addEventListener('load', function () {
			response = JSON.parse(request.response);

			if (!response.success) {
				alertUser(document.getElementById('main'), 'failure', response.message);
				return;
			}

			argon2.hash({pass: password.value, salt: response.message, time: 20, type:argon2.ArgonType.Argon2id}).then(function (hash) {
				request = new XMLHttpRequest();
				request.open('POST', '/api/auth/login', true);
				request.send(JSON.stringify({'username': username.value, 'passwordHash': hash.encoded, 'totp': totp.value}));

				request.addEventListener('load', function () {
					response = JSON.parse(request.response);

					if (response.success) {
						alertUser(document.getElementById('main'), 'success', response.message);
						window.location.href = '/dashboard';
//						window.history.replaceState({}, 'Logged in', '/logged_in');
						return;

					} else if (response.data === '') {
						alertUser(document.getElementById('main'), 'failure', response.message);
						return
					}

					data = JSON.parse(response.data);
					console.log(data);

					if (data.webauthn === '') {
						alertUser(document.getElementById('main'), 'failure', response.message);
						return;
					}

					webauthn = JSON.parse(data.webauthn);
					console.log(webauthn);

					webauthn.publicKey.challenge = bufferDecode(webauthn.publicKey.challenge);

					webauthn.publicKey.allowCredentials.forEach(function (listItem) {
						listItem.id = bufferDecode(listItem.id)
					});

					navigator.credentials.get({
						publicKey: webauthn.publicKey

					}).then((assertion) => {
						let authData = assertion.response.authenticatorData;
						let clientDataJSON = assertion.response.clientDataJSON;
						let rawId = assertion.rawId;
						let sig = assertion.response.signature;
						let userHandle = assertion.response.userHandle;

						request = new XMLHttpRequest();
						request.open('POST', '/api/auth/login', true);
						request.send(JSON.stringify({
							username: username.value,
							passwordHash: hash.encoded,
							id: assertion.id,
							rawId: bufferEncode(rawId),
							type: assertion.type,
							response: {
								authenticatorData: bufferEncode(authData),
								clientDataJSON: bufferEncode(clientDataJSON),
								signature: bufferEncode(sig),
								userHandle: bufferEncode(userHandle),
							},
						}));

						request.addEventListener('load', function () {
							response = JSON.parse(request.response);

							if (response.success) {
								alertUser(document.getElementById('main'), 'success', response.message);
//								window.history.replaceState({}, 'Logged in', '/logged_in');
								window.location.href = '/dashboard';
//								window.location.href = '/logged_in';
							} else {
								alertUser(document.getElementById('main'), 'failure', response.message);
							}
						});

					}).catch(function (error) {
						alertUser(document.getElementById('main'), 'failure', 'Webauthn authentication failed.');
					});
				});
			});
		});
	}
}

/*function login() {
	username = document.getElementById('username');
	password = document.getElementById('password');

	if (username != null && password != null) {
		makeJSONRequest('/api/auth/salt', {'username': username.value}, 'POST').then(function (response) {
			if (response.success) {
				argon2.hash({pass: password.value, salt: response.message, time: 20, type:argon2.ArgonType.Argon2id}).then(function (hash) {
					makeJSONRequest('/api/auth/login', {'username': username.value, 'passwordHash': hash.encoded}, 'POST').then(function (response) {
						if (response.success) {
							window.location.href = '/logged_in';
						}
					});
				});
			}
		});
	}
}*/

function register(event) {
	if (event && event.type !== 'click' && (event.type == 'keydown' && event.code !== 'Enter')) {
		return;
	}

	username = document.getElementById('username');
	password = document.getElementById('password');

	if (username != null && password != null) {
		if (window.crypto == undefined) {
			salt = '' + Math.random() + Math.random();

		} else {
			salt = bufferToBase64String(crypto.getRandomValues(new Uint8Array(64)));
		}

		argon2.hash({pass: password.value, salt: salt, time: 20, type:argon2.ArgonType.Argon2id}).then(function (hash) {
			makeJSONRequest('/api/auth/register', {'username': username.value, 'passwordHash': hash.encoded, 'salt': salt}, 'POST').then(function (response) {
				if (response.success) {
					alertUser(document.getElementById('main'), 'success', response.message);
					window.location.href = '/dashboard';
//					window.history.replaceState({}, 'Registered', '/registered');

				} else {
					alertUser(document.getElementById('main'), 'failure', response.message);
				}
			});
		});
	}
}

async function makeJSONRequest(url, data, method='GET') {
	const response = await fetch(url, {
		method: method,
		mode: 'cors', // no-cors, *cors, same-origin
		cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
		credentials: 'same-origin', // include, *same-origin, omit
		headers: {
			'Content-Type': 'application/json'
		},
		redirect: 'follow', // manual, *follow, error
		referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
		body: JSON.stringify(data)
	});

	return response.json(); // parses JSON response into native JavaScript objects
}

function bufferToBase64String(buffer) {
	var view = new Uint8Array(buffer);
	var string = '';

	for (i = 0; i < view.length; i ++) {
		string += String.fromCharCode(view[i]);
	}

	return btoa(string);
}

function bufferDecode(value) {
	return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function registerTOTP() {
	makeJSONRequest('/api/auth/register/totp', {}, 'POST').then((totpResponse) => {
		if (!totpResponse.success) {
			alertUser(document.getElementById('main'), 'failure', totpResponse.message);
			return;
		}

		image = document.createElement("img");

		QRCode.toDataURL(totpResponse.data).then((uri)=>{
			console.log(uri);
			image.src=uri;
			console.log(image);
			document.body.appendChild(image)
		});

		console.log(totpResponse);
		alertUser(document.getElementById('main'), 'success', totpResponse.message);
	});
}

function registerWebauthn() {
	makeJSONRequest('/api/auth/register/webauthn/begin', {
//		username: username,

	}, 'POST').then((credentialCreationOptions) => {
		credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
		credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);

		if (credentialCreationOptions.publicKey.excludeCredentials) {
			for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
				credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
			}
		}

		return navigator.credentials.create({
			publicKey: credentialCreationOptions.publicKey
		});

	}).then((credential) => {
		attestationObject = credential.response.attestationObject;
		clientDataJSON = credential.response.clientDataJSON;
		rawId = credential.rawId;

		return makeJSONRequest('/api/auth/register/webauthn/finish', {
//			username: username,
			id: credential.id,
			rawId: bufferEncode(rawId),
			type: credential.type,
			response: {
				attestationObject: bufferEncode(attestationObject),
				clientDataJSON: bufferEncode(clientDataJSON),
			},

		}, 'POST')

	}).then((response) => {
		if (response.success) {
			alertUser(document.getElementById('main'), 'success', 'Successfully registered.');

		} else {
			alertUser(document.getElementById('main'), 'failure', 'Failed to register webauthn.');
		}

		return;

	}).catch((error) => {
		alertUser(document.getElementById('main'), 'failure', 'Failed to register webauthn.');
		console.log(error);
	});
}

function bufferEncode(value) {
	return btoa(String.fromCharCode.apply(null, new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');;
}
