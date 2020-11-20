const app=require('express')();
const cors=require('cors');
const denv=require('dotenv');
const BodyParser=require('body-parser');
const mongoose = require('mongoose');
const Router =require('./Routes/Auth');


const PORT=8000||process.env.PORT
denv.config()

app.use(cors());
app.use(BodyParser.json());

app.use('/auth',Router)

app.listen(PORT,()=>{
	mongoose.connect(process.env.DB_URI,{
		useUnifiedTopology: true,
		useNewUrlParser:true
	})
	const db = mongoose.connection;
	db.on('error', console.error.bind(console, 'connection error:'));
	db.once('open', function () {
		console.log('connected to db');
		console.log(`server started at ${PORT}`);
	});
});
