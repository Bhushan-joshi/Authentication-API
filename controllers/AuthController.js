const User = require('../models/User');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const sgMail = require('@sendgrid/mail');
const activate = require('../templates/NewUser')

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