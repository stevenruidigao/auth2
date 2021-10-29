if (!document.cookie.includes('token')) {
	window.location.href = '/login';
}

document.getElementById('totp').onclick = registerTOTP;
document.getElementById('webauthn').onclick = registerWebauthn;

