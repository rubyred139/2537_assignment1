
require("./utils.js");

require('dotenv').config();

const url = require("url");

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
	return (req.session.authenticated);
}

function sessionValidation(req, res, next) {
	if (isValidSession(req)) {
		next();
	} else {
		res.redirect('/login');
	}
}

function isAdmin(req) {
	return (req.session.user_type == "admin");

}

function adminAuthorization(req, res, next) {
	if (!isAdmin(req)) {
		res.status(403);
		res.render("errorMessage", {error:"Not Authorized!", navLinks: navLinks, currentURL: url.parse(req.url).pathname})
	} else {
		next;
	}
}

const navLinks = [
	{name: "Home", link: "/"},
	{name: "Admin", link:"/admin"},
	{name: "Login", link:"/login"},
	{name: "Signup", link:"/signup"},
	{name: "Members Area", link: "/members"},
	{name: "Sign Out", link:"/signout"}
]

app.get('/', (req,res) => {
	console.log(req.url);
	console.log(url.parse(req.url).pathname);
	const authenticated = req.session.authenticated;
	res.render('index', {authenticated: authenticated, navLinks: navLinks, currentURL: url.parse(req.url).pathname});

});

app.use("/members", sessionValidation);
app.get("/members", (req,res) => {
	var username = req.session.username;
	var email = req.session.email
	console.log(req.session);
    res.render('members', {user: username, navLinks: navLinks, currentURL: url.parse(req.url).pathname});    

})

app.get('/nosql-injection', async (req,res) => {
	var username = req.session.email;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

// app.get('/about', (req,res) => {
//     var color = req.query.color;

//     res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
// });

// app.get('/contact', (req,res) => {
//     var missingEmail = req.query.missing;
//     var html = `
//         email address:
//         <form action='/submitEmail' method='post'>
//             <input name='email' type='text' placeholder='email'>
//             <button>Submit</button>
//         </form>
//     `;
//     if (missingEmail) {
//         html += "<br> email is required";
//     }
//     res.send(html);
// });

// app.post('/submitEmail', (req,res) => {
//     var email = req.body.email;
//     if (!email) {
//         res.redirect('/contact?missing=1');
//     }
//     else {
//         res.send("Thanks for subscribing with your email: "+email);
//     }
// });


app.get('/signup', (req,res) => {
    res.render('createUser', {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});


app.get('/login', (req,res) => {
	// var invalidPassword = req.query.msg;
    // if (invalidPassword) {
    //     html += "<br> Invalid email/password combination" ;
    // }
    res.render('login', {navLinks: navLinks, currentURL: url.parse(req.url).pathname});

});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

	if (!username || !email || !password) {
		// Create an object to hold the missing fields
		const missingFields = {};
	
		// Add missing fields to the object
		if (!username) {
		  missingFields.username = 'Username';
		}
		if (!email) {
		  missingFields.email = 'Email';
		}
		if (!password) {
		  missingFields.password = 'Password';
		}
	
		// Generate the error message
		const errorMessage = Object.entries(missingFields)
		  .map(([field, label]) => `${label} is required`)
		  .join('. ');
	
		const html = `
		<p>${errorMessage}</p>
		<a href="/signup">Try again</a>
		`; 
		// Render the error message with a link back to the login page
		res.send(html);
		return;
	  }

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});


	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	console.log("Inserted user");

    // Log the user in by setting the session variables
    req.session.authenticated = true;
    req.session.email = email;
	req.session.username = username;
    // var html = "successfully created user";
    res.redirect("/members");
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, _id: 1, username: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
        res.send("Invalid email/password combination");
		console.log("user not found");
		res.render('login');
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;
		req.session.username = result[0].username;

		res.redirect('/members');
		return;
	}
	else {
		res.send("Invalid email/password combination")
		console.log("incorrect password");
		res.redirect("/login");
        
		return;
	}
});


// app.get('/loggedin', (req,res) => {
//     if (!req.session.authenticated) {
//         res.redirect('/login');
//     }
//     var html = `
//     You are logged in!
//     `;
//     res.send(html);
// });

app.get('/signout', (req,res) => {
	req.session.destroy();
    res.render('index', {authenticated: false, navLinks:navLinks ,currentURL: url.parse(req.url).pathname});
});


// app.get('/cat/:id', (req,res) => {

//     var cat = req.params.id;

//     if (cat == 1) {
//         res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
//     }
//     else if (cat == 2) {
//         res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
//     }
//     else {
//         res.send("Invalid cat id: "+cat);
//     }
// });

app.get('/admin', sessionValidation, adminAuthorization, async(req,res) => {

	const result = await userCollection.find().project({username: 1, _id: 1}).toArray();
	res.render('admin', {users: result, navLinks:navLinks, currentURL: url.parse(req.url).pathname});
})

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
    res.status(404);
    res.render('404', {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 