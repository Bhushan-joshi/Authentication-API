const newLogin = (name, device, ip, date,os,geoIP) => {
	return `
	<div style="text-align: center;">
	<h2>We Noticed a New Login,</h2>
	<h3> ${name}</h3><br/>
	<p>Device <strong>${device} </strong></p>
	<p>IP <strong>${ip.split(":")[3]} </strong></p>
	<p>OS <strong>${os} </strong></p>
	<p>geoIP <strong>${geoIP} </strong></p>
	<p><strong>${date} </strong></p>
	<br>
	</div>`
}
module.exports = newLogin;