const express = require('express')
const escape = require('escape-html');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser')
const csrf = require('csurf')
const KJUR = require('jsrsasign').KJUR
const jwt = require('jsonwebtoken')

const app = express()

//////////////
// Boiletplate

// csrf
const csrfProtection = csrf({ cookie: true })
app.use(cookieParser())

// POST data
app.use(bodyParser.json()); // for parsing application/json
const parseForm = app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded

// templates
var fs = require('fs') // this engine requires the fs module
app.engine('ntl', function (filePath, options, callback) { // define the template engine
  fs.readFile(filePath, function (err, content) {
    if (err) return callback(err)
    // this is an extremely simple template engine
    var rendered = content.toString()
    for (const [key, value] of Object.entries(options.params)) {
        rendered = rendered.replace(`#${key}#`, value)
    }
    return callback(null, rendered)
  })
})
app.set('views', './templates') // specify the views directory
app.set('view engine', 'ntl') // register the template engine


//////////////////////////////
// App code

app.get('/', csrfProtection, (req, res) => {
    res.render('index', {params:{'csrfToken': req.csrfToken()}})
})

app.post('/unsecure', (req, res) => {
    res.set('X-XSS-Protection', '0');
    res.render('submit', {params: {'posted_value': req.body.vulnerable}})
})

app.post('/chrome_protect', (req, res) => {
    res.render('submit', {params: {'posted_value': req.body.vulnerable}})
})

app.post('/referer_check', (req, res) => {
    res.set('X-XSS-Protection', '0');
    if(!req.headers.referer.startsWith("https://bob-cloud-computing.tk/")) {
        res.send('Bad referer')
    } else {
        res.render('submit', {params: {'posted_value': req.body.vulnerable}})
    }
})

app.post('/source_self', (req, res) => {
    res.set('X-XSS-Protection', '0');

    var csp = [
        "script-src 'self'",
        "report-uri https://sentry.io/api/1189287/csp-report/?sentry_key=6a8127a98f32458daf9e82be16903f56"
    ].join(";")
    res.set('Content-Security-Policy', csp)

    res.render('submit', {params: {'posted_value': req.body.vulnerable}})
})

app.post('/no_extract', (req, res) => {
    res.set('X-XSS-Protection', '0');

    var csp = [
        "connect-src 'self'",
        "default-src *",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self'",
        "img-src 'self' data:",
        "report-uri https://sentry.io/api/1189287/csp-report/?sentry_key=6a8127a98f32458daf9e82be16903f56"
    ].join(";")
    res.set('Content-Security-Policy', csp)

    res.render('submit', {params: {'posted_value': req.body.vulnerable}})
})

app.post('/escape', (req, res) => {
    res.set('X-XSS-Protection', '0');
    res.render('submit', {params: {'posted_value': escape(req.body.vulnerable)}})
})

app.post('/crsf', csrfProtection, (req, res) => {
    res.set('X-XSS-Protection', '0');
    res.render('submit', {params: {'posted_value': req.body.vulnerable}})
})


app.get('/login', csrfProtection, (req, res) => {
    res.render('login', {params:{'csrfToken': req.csrfToken()}})
})
app.post('/login', (req, res) => {
    var username = req.body.username
    var password = req.body.password
    console.log(username, password)
    if(username == "admin" && password == "toor") {
        var ip = req.headers['x-real-ip']
        if(ip === undefined) {
            ip = '1.1.1.1' // Test for dev when not behind the nginx proxy
        }

        var oHeader = {alg: 'HS256', typ: 'JWT'};
        var oPayload = {};
        oPayload.username = "admin"
        oPayload.ip = ip

        var sHeader = JSON.stringify(oHeader);
        var sPayload = JSON.stringify(oPayload);
        var sJWT = KJUR.jws.JWS.sign("HS256", sHeader, sPayload, "MY secret");

        res.cookie('auth', sJWT, { maxAge: 900000, httpOnly: false })
        res.redirect('/admin');
    } else {
        res.render('login', {params:{}})
    }
})

app.get('/admin', (req, res) => {
    var ip = req.headers['x-real-ip']
    if(ip === undefined) {
        ip = '1.1.1.1' // Test for dev when not behind the nginx proxy
    }

    var token = req.cookies.auth
    if(token === undefined) {
        res.send('No cookie found')
    } else {
        var decoded = jwt.verify(token, 'MY secret');
        if(decoded.username != 'admin') {
            res.send('Bad user')
        } else {
            if(decoded.ip != ip) {
                res.send("Bad ip")
            } else {
                res.render('admin', {params:{'ip': ip}})
            }
        }
    }
})


app.listen(8210, () => console.log('Bob app listening on port 8210!'))
