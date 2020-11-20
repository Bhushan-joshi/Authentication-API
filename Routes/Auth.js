const { Router } = require("express");
const controllers = require('../controllers/AuthController');
const { check, body } = require('express-validator');



Router.post('/signup',
	[check('email').normalizeEmail().isEmail().withMessage('Invalid Email !'),
	body('firstName').isLength({ min: 4 }).withMessage('Name must be of 4 Characters long '),
	body('lastName').isLength({ min: 4 }).withMessage('Name must be of 4 Characters long '),
	body('password').isAlphanumeric().isLength({ min: 8 }).withMessage('Password must be of 8 Characters long and Alphanumeric!'),]
	, controllers.postSignup);


module.exports = Router;