const activateUser=(name,email,token)=>{
	return `
	<h1>Hello ${name},</h1>
	<p>Pease click on the button to complete the verification process for ${email}</p>
	<a href='http://localhost:8000/auth/activate/${token}'>VERIFY YOUR EMAIL ADDRESS</a>
	<p><strong>Valid only for 5 minute</strong></p>`
}
module.exports=activateUser;