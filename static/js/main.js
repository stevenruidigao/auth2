function goLogin() {
	window.location.href = '/login';
}

function goRegister() {
	window.location.href = '/register';
}

function login() {
	username = document.getElementById('username');
	password = document.getElementById('password');

	if (username != null && password != null) {
		request = new XMLHttpRequest();
		request.open('POST', '/api/auth/salt', true);
		request.send(JSON.stringify({'username': username.value}));

		request.addEventListener('load', function () {
			response = JSON.parse(request.response);

			if (response.success) {
				argon2.hash({pass: password.value, salt: response.message, time: 20, type:argon2.ArgonType.Argon2id}).then(function (hash) {
					request = new XMLHttpRequest();
					request.open('POST', '/api/auth/login', true);
					request.send(JSON.stringify({'username': username.value, 'passwordHash': hash.encoded}));

					request.addEventListener('load', function () {
						response = JSON.parse(request.response);

						if (response.success) {
//							window.location.href = '/logged_in';
						}
					});
				});
			}
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

function register() {
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
					window.location.href = '/registered';
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

