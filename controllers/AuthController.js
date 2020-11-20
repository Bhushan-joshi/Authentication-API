const User = require('../models/User');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
const activate = require('../templates/newuser')
const forgotPassword = require('../templates/forgotPassword');
const newLogin = require('../templates/newLogin')
const userAgent = require('express-useragent');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');


const signInMail = (email,name, device, ip, date, os, geoIp) => {
	sgMail.setApiKey(process.env.SG_KEY);
	const message = {
		to: email,
		from: {
			name: 'Ebuy',
			email: 'pathareketan1@gmail.com'
		},
		subject: 'New Login !',
		html: newLogin(name, device, ip, date, os, geoIp),
	}
	sgMail.send(message).then(res => {
		console.log({...res});
	}).catch(err => {
		console.log({...err});
	})
}


exports.postSignup = (req, res) => {
	const auth = crypto.randomBytes(32).toString('hex');
	const { firstName, lastName, email, password } = req.body
	const errors = validationResult(req);
	User.findOne({ email: email }).then(user => {
		if (user) {
			return res.status(400).json({
				message: 'userExist'
			})
		}
		const salt = crypto.randomBytes(32).toString('hex');
		const hash = crypto.pbkdf2Sync(password, salt, 10, 32, 'sha256').toString('hex');
		const newUser = new User({
			firstName: firstName,
			lastName: lastName,
			email: email,
			salt: salt,
			hash: hash,
			activationToken: auth,
			activationTokenCreatedOn: (Date.now() + 300000).toString(),
		})
		if (errors.isEmpty()) {
			newUser.save().then(userSave => {
				sgMail.setApiKey(process.env.SG_KEY);
				const message = {
					to: userSave.email,
					from: {
						name: 'Ebuy',
						email: 'pathareketan1@gmail.com'
					},
					subject: 'Account Activation for Ebuy',
					html: activate(userSave.firstName, userSave.email, auth),
				}

				sgMail.send(message).then(email => {
					res.status(201).json({
						message: 'user created ',
						email: 'mail send'
					})
				}).catch(err => {
					res.status(500).json({
						message: "Something went wrong ! unable to send Email",
						email: false,
					})
				})
			}).catch(err => {
				console.log(err);
				res.status(500).json({
					...err,
					message: "unable to process the request "
				})
			})
		} else {
			console.log(errors);
			res.status(400).json({
				message: errors.errors[0].msg
			})
		}
	}).catch(err => {
		console.log(err);
		res.status(500).json({
			message: "Something went Wrong on our end ! please try again",
			email: false,
		})
	})
}

exports.postAccountActivation = (req, res) => {
	const token = req.params.token;
	User.findOne({ activationToken: token }).then(user => {
		if (user.activationTokenCreatedOn > Date.now().toString()) {
			user.activated = true;
			user.activationToken = undefined;
			user.activationTokenCreatedOn = undefined;
		} else {
			user.activationTokenCreatedOn = undefined;
			user.activationToken = undefined;
			user.activate = false;
		}
		user.save();
	}).catch(err => {
		console.log(err);
	})
	res.redirect('http://127.0.0.1:3000/signin')
}

exports.postSignin = (req, res) => {
	const { email, password, otp } = req.body;
	User.findOne({ email: email })
		.then(user => {
			if (!user.activated) {
				return res.status(400).json({
					message: 'Please verify your email address'
				})
			}
			const salt = user.salt;
			const hash = crypto.pbkdf2Sync(password, salt, 10, 32, 'sha256').toString('hex');
			if (hash === user.hash) {
				if (user.is2FA) {
					const validate = speakeasy.totp.verify({
						secret: user.twoFactorAuth.base32,
						encoding: 'base32',
						token: otp,
					})
					if (validate) {
						const token = jwt.sign({
							id: user.id
						}, process.env.KEY, { algorithm: `HS256`, expiresIn: '3600s' })
						const decode = jwt.decode(token);
						res.setHeader('Authorization', token)
						res.status(200).json({
							token: token,
							is2FA: user.is2FA,
							expiresIn: decode.exp,
							message: "login successfully"
						})
						const source = req.headers["user-agent"]
						const userA = userAgent.parse(source);
						signInMail(user.email,user.firstName, userA.browser, req.ip, new Date().toLocaleString(), userA.os, userA.geoIp)
					} else {
						res.status(400).json({
							message: 'Error! Invalid OTP!',
						})
					}
				} else {
					const token = jwt.sign({
						id: user.id
					}, process.env.KEY, { algorithm: `HS256`, expiresIn: '3600s' })
					const decode = jwt.decode(token);
					res.setHeader('Authorization', token)
					res.status(200).json({
						token: token,
						is2FA: user.is2FA,
						expiresIn: decode.exp,
						message: "login successfully"
					})
					const source = req.headers["user-agent"]
					const userA = userAgent.parse(source);
					signInMail(user.email,user.firstName, userA.browser, req.ip, new Date().toLocaleString(), userA.os, userA.geoIp)
				}
			} else {
				res.status(400).json({
					message: 'Invalid Email or password ',
				})
			}
		}).catch(err => {//findOne's catch block
			res.status(500).json({
				...err,
				message: 'Invalid Email or password ',
			})
		})
}

exports.getForgotPassword = (req, res) => {
	const { email } = req.body;
	User.findOne({ email: email }).then(user => {
		if (!user) {
			res.status(400).json({
				message: 'No users found',
			})
		} else {
			crypto.randomBytes(64, (error, buffer) => {
				if (error) {
					return res.status(500).json({
						message: "Something went Wrong on our end ! please try again",
					})
				}
				const token = buffer.toString('hex');
				user.forgotPasswordToken = token;
				user.forgotPasswordTokenCreatedOn = (Date.now() + 900000).toString()
				user.save().then(userSave => {
					sgMail.setApiKey(process.env.SG_KEY);
					const message = {
						to: userSave.email,
						from: {
							name: 'Ebuy',
							email: 'pathareketan1@gmail.com'
						},
						subject: 'Password Reset',
						html: forgotPassword(userSave.firstName, userSave.email, userSave.forgotPasswordToken),
					}
					sgMail.send(message).then(email => {
						res.status(200).json({
							email: 'mail send'
						})
					}).catch(err => {
						res.status(500).json({
							message: "Something went wrong ! unable to send Email"
						})
					})
				})
			})
		}
	})
}

exports.postResetPassword = (req, res) => {
	const { token, confirmPassword, password } = req.body;
	User.findOne({ forgotPasswordToken: token, forgotPasswordTokenCreatedOn: { $gt: Date.now().toString() } })
		.then(user => {
			if (password === confirmPassword) {
				const hash = crypto.pbkdf2Sync(password, user.salt, 10, 32, 'sha256');
				user.hash = hash.toString('hex');
				user.forgotPasswordTokenCreatedOn = undefined;
				user.forgotPasswordToken = undefined;
				user.save();
				res.status(200).json({
					message: "password change sucessfully!"
				})
			} else {
				res.status(400).json({
					message: "password must match!"
				})
			}
		}).catch(err => {
			res.status(500).json({
				message: "Something went wrong ! unable to save password"
			})
		})
}

exports.postChangePassword = (req, res) => {
	const { oldPassword, newPassword, confirmNewPassword } = req.body;
	User.findById(req.user).then(user => {
		const hash = crypto.pbkdf2Sync(oldPassword, user.salt, 10, 32, 'sha256').toString('hex');
		if (hash === user.hash) {
			if (newPassword === confirmNewPassword) {
				const newhash = crypto.pbkdf2Sync(newPassword, user.salt, 10, 32, 'sha256').toString('hex');
				user.hash = newhash;
				user.save().then(saveUser => {
					res.status(200).json({
						message: "Password change successfully"
					})
				}).catch(err => {
					console.log(err);
					res.status(500).json({
						message: "Enable to change password "
					})
				})
			} else {
				return res.status(400).json({
					message: "Password fields must match!"
				})
			}

		} else {
			return res.status(400).json({
				message: "Please enter correct password"
			})
		}
	}).catch(err => {
		res.status(400).json({
			message: "No user found !",
			...err
		})
	})
}

exports.postEnable2FA = (req, res) => {
	User.findById(req.user).then(user => {
		if (!user.is2FA) {
			const tempSecret = speakeasy.generateSecret();
			user.is2FA = true;
			user.twoFactorAuth = tempSecret;
			qrcode.toDataURL(tempSecret.otpauth_url).then(qr => {
				user.save().then(saveUser => {
					res.status(200).json({
						message: "enabled 2FA!",
						qrcode: qr,
						base32: saveUser.twoFactorAuth.base32,
						is2FA: user.is2FA,
					})
				}).catch(err => {
					console.error(err);
					res.status(500).json({
						message: "Something went wrong !"
					})
				})
			}).catch(err => {
				console.log(err);
			})
		}else{
			qrcode.toDataURL(user.twoFactorAuth.otpauth_url).then(code=>{
				res.status(200).json({
					message: "Already enabled 2FA!",
					qrcode: code,
					base32: user.twoFactorAuth.base32,
					is2FA: user.is2FA,
				})
			})
		}
	}).catch(err => {
		console.log(err);
		res.status(500).json({
			message: "Something went wrong ! unable find user"
		})
	})
}


exports.postVerifyTOTP = (req, res) => {
	const { token } = req.body;
	User.findById(req.user).then(user => {
		const verify = speakeasy.totp.verify({
			secret: user.twoFactorAuth.base32,
			encoding: 'base32',
			token: token
		});
		res.json({
			verify: verify
		})
		console.log(verify);
	}).catch(err => {
		console.error(err);
		res.status(500).json({
			message: "Something went wrong ! unable find user"
		})
	})
}