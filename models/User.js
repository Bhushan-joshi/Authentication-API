const mongoose=require('mongoose');

const Schema=mongoose.Schema

const userShema=new Schema({
	firstName:{
		type:String,
		required:true
	},
	lastName:{
		type:String,
		required:true,
	},
	email:{
		type:String,
		required:true,
		lowercase:true
	},
	salt:{
		type:String,
		required:true,
	},
	hash:{
		type:String,
		required:true,
	},
	createdOn:{
		type:Date,
		default:Date.now()
	},
	activated:{
		type:Boolean,
		default:false
	},
	activationToken:{
		type:String,
	},
	activationTokenCreatedOn:{
		type:String,
	},
	forgotPasswordToken:{
		type:String,
	},
	forgotPasswordTokenCreatedOn:{
		type:String
	},
});

module.exports = mongoose.model('User', userShema);