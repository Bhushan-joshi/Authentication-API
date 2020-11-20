const forgotPassword = (name, email, token) => {
	return`
	<h1>Hello ${name},</h1>
	<p>You're receiving this e-mail because you or someone else has requested a password for your user account.
	It can be safely ignored if you did not request a password reset. Click the link below to reset your password</p>
	<a href='http://127.0.0.1:3000/accounts/reset?token=${token}'>RESET PASSWORD</a>
	<br>
	<p>In case you forgot, your username is ${email}.</p>
<br>
	<p><strong>Valid only for 15 minute</strong></p>`
}
module.exports = forgotPassword;