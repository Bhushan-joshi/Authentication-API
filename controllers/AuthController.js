const User = require('../models/User');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
const activate = require('../templates/NewUser')
const userAgent = require('express-useragent');
const newLogin = require('../templates/newLogin')

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
				signInMail(user.email, user.firstName, userA.browser, req.ip, new Date().toLocaleString(), userA.os, userA.geoIp)
			} else {
				res.status(400).json({
					message: 'Invalid Email or password ',
				})
			}
		}).catch(err => {
			res.status(500).json({
				...err,
				message: 'Invalid Email or password ',
			})
		})
}