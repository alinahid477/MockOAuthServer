const cors = require('cors');
const express = require('express');
var url = require('url');
var redis = require('redis');
require('dotenv').config();

var redisURL = url.parse(process.env.REDIS_URL);
var redisClient = redis.createClient(redisURL.port, redisURL.hostname, {no_ready_check: true});
redisClient.auth(redisURL.auth.split(":")[1]);

const port = process.env.PORT;

const app = express();
app.use(cors());
app.use(express.json());

const eligible_accesses = new Set();
const accessTokens = new Set();

eligible_accesses.add({clientId:'1111', clientSecret:'secret1'});
eligible_accesses.add({clientId:'2222', clientSecret:'secret2'});
eligible_accesses.add({clientId:'3333', clientSecret:'secret3'});
eligible_accesses.add({clientId:'4444', clientSecret:'secret4'});
eligible_accesses.add({clientId:'5555', clientSecret:'secret5'});
eligible_accesses.add({clientId:'6666', clientSecret:'secret6'});

app.get('/healthcheck', (req, res) => {
    return res.status(200).json({message:'I am working... eff off'});
});

app.post('/auth/token', (req, res) => {
    if (req.body.grantType === 'client_credentials') { 
        for (const item of eligible_accesses) {
            if(item.clientId === req.body.clientId && item.clientSecret === req.body.clientSecret ) {
                const token = new Array(50).fill(null).map(() => Math.floor(Math.random() * 10)).join('');
                redisClient.set(token, `${req.body.clientId}-${req.body.clientSecret}`);
                return res.status(200).json({ 'access_token': token, 'expires_in': 60 * 60 * 24, 'token_type':'Bearer' });
            }
        }
        return res.status(400).json({ message: 'Invalid credential' });  
        // Generate a string of 50 random digits
        
    } else {
      res.status(400).json({ message: 'Invalid grant type' });
    }
  });

  app.post('/receive/secure', (req, res) => {
    let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
    if (token && token.startsWith('Bearer ')) {
        // Remove Bearer from string
        token = token.slice(7, token.length);
    }
    if (!token) {
      return res.status(403).json({ message: 'Unauthorized' });
    }
    return redisClient.get(token, function (err, reply) {
        console.log(reply);
        if (reply != null) {
            for (const item of eligible_accesses) {
                if(`${item.clientId}-${item.clientSecret}` === reply) {
                    return res.status(200).json(req.body);
                }
            }
            return res.status(400).json({message:'authorisation denied'});
        } else {
            res.status(400).json({message:'authorisation denied'});
        }
      });
    
  });

  app.get('/auth/token/remove', (req, res) => {
    let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
    if (token && token.startsWith('Bearer ')) {
        // Remove Bearer from string
        token = token.slice(7, token.length);
    }
    console.log("remove: ",token);
    if (!token) {
      return res.status(403).json({ message: 'Unauthorized' });
    }
    return redisClient.del(token, function (err, response) {
        if (response === 1) {
            return res.status(200).json({message:'removed successfully'});
        } else {
            return res.status(400).json({message:'cannot remove'});
        }
      });
    
  });


  app.listen(port, () => {
    console.log(`OAuthServer started and listening on port ${port}`);
  });