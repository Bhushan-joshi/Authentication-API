# Authentication API

This is an Authentication API using JWT's that you can plug inside your current project or you can start with a new one. Email & Password (TOTP) is used for authentication.

The API based on Node.js, Express, MongoDB , following the **MVC pattern** i.e. Model ~~View~~ Controller.

**Mongoose** is used for storing Users in Database.


---

## To start setting up the project

Step 1: Clone the repo

```bash
git clone https://github.com/Bhushan-joshi/Authentication-API.git
```

Step 2: cd into the cloned repo and run:

```bash
npm i
```

Step 3: Put your credentials in the .env file.

```bash
DB_URI='Your Mongodb URl'
KEY='Secret for signing jwt'
SG_KEY='Send grid API key for sending Emails'
```

Step 4: Install MongoDB (Linux Ubuntu)

See <https://docs.mongodb.com/manual/installation/> for more infos

Step 5: start mongodb service

```bash
sudo systemctl  start mongodb.service 
```

Step 6: Start the API by

```bash
npm start
```

Step 7 (Optional): for DEBUG 

```bash
npm run dev
```

---

## Contribute

You can fork this repo and send me a PR.