const jwt = require('jsonwebtoken');
const axios = require('axios');
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

eligible_accesses.add({clientSecret:'secret1'});
eligible_accesses.add({clientSecret:'secret2'});
eligible_accesses.add({clientSecret:'secret3'});
eligible_accesses.add({clientSecret:'secret4'});
eligible_accesses.add({clientSecret:'secret5'});
eligible_accesses.add({clientSecret:'secret6'});

app.get('/healthcheck', (req, res) => {
    return res.status(200).json({message:'I am working... eff off'});
});

app.get('/', (req, res) => {
    return res.status(200).json({
        message:'Welcome to simple OAuth Server Mock - by Ali Nahid',
        usage:[
            {
                endpoint:'/healthcheck',
                method:'GET',
                description:'to healthcheck auth server'
            },
            {
                endpoint:'/auth/token',
                method:'POST',
                description:'Requst Body must contain clientId, clientSecret, grantType. you can use any client id, just use a unique one. \
                                clientSecret: must be one of these secret1,secret2,secret3,secret4,secret5,secret6 \
                                grantType must be client_credentials',
                sampleRequest: {
                    clientId:'myuniqueclientid',
                    clientSecret:'secret1',
                    grantType:'client_credentials'
                },
                sampleResponse:{
                    access_token:'generated granted token, This token is cached for 30 days unless you remove it.',
                    expires_in:'expiry time',
                    token_type:'Bearer'
                }
            },
            {
                endpoint:'/auth/token/remove',
                method:'GET',
                description:'Remove the token you have been granted. Please clean up after yourself.',
                sampleRequest: {
                    header: {
                        Authorization: 'Bearer <your token>'
                    },
                    body:{
                        forwardUrl:'url where the response/outcome will be fowarded to'
                    }
                },
                sampleResponse:{
                    message:'removed successfully or failed to remove'
                }
            },

            {
                endpoint:'/receive/secure',
                method:'POST',
                description:'post any payload with authorization header with the granted token',
                sampleRequest: {
                    header: {
                        Authorization: 'Bearer <your token, granted from /auth/token endpoint>'
                    },
                    body: 'your request body. whatever body it is. This endpoint will output and forward the body if authorization is successful and forward to the url supplied via forwardUrl attribute. Please supply a forwardUrl to see response to the forward url. Thus this acts as a relayer between ENS and your endpoint.'
                    
                },
                sampleSuccessfulResponse:'If authorisation is successful this the response body will contain whatever body you supplied in the request payload with 200 response code. and will forward the response to the forwardurl supplied in the request body.',
                sampleFailedResponse:'If authorisation is not successful then the response will be a 400 code and error is forwarded to the supplied forwardUrl'
            },
            {
                endpoint:'/receive/registerforwardurl',
                method:'POST',
                description:'register a forward url so that this can act as a relayer between ens and your endpoint.',
                sampleRequest: {
                    header: {
                        Authorization: 'Bearer <your token, granted from /auth/token endpoint>'
                    },
                    body: {
                        forwardUrl:'your forward url'
                    }                    
                },
                sampleSuccessfulResponse:'If authorisation is successful this the response body with 200 response code and forward url is successfully associated with token. and will forward the response to the forwardurl supplied in the request body.',
                sampleFailedResponse:'If authorisation is not successful then the response will be a 400 code and error is forwarded to the supplied forwardUrl'
            },
        ]
    });
});

app.post('/auth/token', (req, res) => {
    try {
        console.log(req.headers);
        console.log(req.body);

        let basicToken = req.headers['authorization'];
        
        if (basicToken && basicToken.startsWith('Basic ')) {
            basicToken = basicToken.slice(6, basicToken.length);
            if (!basicToken) {
                if(req.body.forwardUrl) {
                    axios.post(req.body.forwardUrl, { message: 'Unauthorized. Basic Token not found.' });
                }            
                return res.status(403).json({ message: 'Unauthorized. Baisc Token not found.' });
            }
            let buff = Buffer.from(basicToken, 'base64');
            let text = buff.toString('utf8');
            const user = text.split(':')[0];
            const pass = text.split(':')[1];
            for (const item of eligible_accesses) {
                if(item.clientSecret === pass ) {
                    const generatedToken = new Array(50).fill(null).map(() => Math.floor(Math.random() * 10)).join('');
                    const tokenExpiry = Date.now() + 60 * 20 * 1000;
                    const tokenObject = { grantedToken: generatedToken, user:user };
                    const token = jwt.sign( tokenObject, process.env.JWT_SIGNING_KEY, { expiresIn: '20m' } );
                    console.log('JWT Token-', token);
                    redisClient.set(token, `${user}-${pass}`);
                    redisClient.set(user, JSON.stringify({token:token}));
                    const responseObj = { access_token:token, 'expires_in': tokenExpiry , 'token_type':'Bearer', scope:'write'};
                    if(req.body.forwardUrl) {
                        axios.post(req.body.forwardUrl, responseObj);
                    }
                    return res.status(200).json(responseObj);
                }
            }
        } else if (req.body.grantType === 'client_credentials' && req.body.clientId) { 
            for (const item of eligible_accesses) {
                if(item.clientSecret === req.body.clientSecret ) {
                    const generatedToken = new Array(50).fill(null).map(() => Math.floor(Math.random() * 10)).join('');
                    const tokenExpiry = Date.now() + 60 * 20 * 1000;
                    const tokenObject = { grantedToken: generatedToken, user:req.body.clientId }
                    const token = jwt.sign( tokenObject, process.env.JWT_SIGNING_KEY, { expiresIn: '20m' } );
                    console.log('JWT Token-', token);
                    redisClient.set(token, `${req.body.clientId}-${req.body.clientSecret}`);
                    redisClient.set(req.body.clientId, JSON.stringify({token:token}));
                    const responseObj = { access_token:token, 'expires_in': tokenExpiry , 'token_type':'Bearer'};
                    if(req.body.forwardUrl) {
                        axios.post(req.body.forwardUrl, responseObj);
                    }
                    return res.status(200).json(responseObj);
                }
            }
            //axios.post(req.body.forwardUrl, { message: 'Invalid credential' });
            return res.status(400).json({ message: 'Invalid credential' });  
            // Generate a string of 50 random digits
            
        } else {
            //axios.post(req.body.forwardUrl, { message: 'Invalid grant type' });
          res.status(400).json({ message: 'Invalid grant type' });
        }
    }catch(err) {
        console.error(err);
    }
    
  });

  app.post('/receive/registerforwardurl', (req, res) => {
    try {
        let user;
        let redisKey;
        let isRedisKeyUserObj = false;
        if(req.body.clientId && req.body.clientSecret) {
            redisKey = req.body.clientId;
            isRedisKeyUserObj = true;
        } else {
            redisKey = req.headers['x-access-token'] || req.headers['authorization'];
            if (redisKey && redisKey.startsWith('Bearer ')) {
                // Remove Bearer from string
                redisKey = redisKey.slice(7, redisKey.length);
            }
        }
      if (!redisKey) {
          if(req.body.forwardUrl) {
              axios.post(req.body.forwardUrl, { message: 'Unauthorized. Token not found.' });
          }            
          return res.status(403).json({ message: 'Unauthorized. Token not found.' });
      }
      return redisClient.get(redisKey, function (err, reply) {
          console.log("found token or userobj:",reply);
          if (reply != null) {
              let token;
              if(isRedisKeyUserObj) {
                  try {
                    token = (JSON.parse(reply)).token;
                  }catch(err){

                  }
              } else {
                  token = redisKey;
              }
              let isValid = false;
              let decoded;
              
              try {
                  decoded = jwt.verify(token, process.env.JWT_SIGNING_KEY);
                  if (decoded.grantedToken) {
                      console.log('valid token', decoded);
                      isValid = true;
                      if(decoded.user) {
                        user = decoded.user;
                      }
                  } else {
                      console.log('invalid token, does not contain grantedtoken or forward url', decoded);
                  }
              } catch (err) {
                  console.error('failed to verify token: ',err);
              }
              if(isValid) {
                  if(isRedisKeyUserObj) {
                    const replyObject = JSON.parse(reply);
                    redisClient.set(user, JSON.stringify({...replyObject, forwardUrl:req.body.forwardUrl}));
                    axios.post(req.body.forwardUrl, {message:'successfully added forwardurl to your granted token.'});
                    return res.status(200).json({message:'successfully added forwardurl to your granted token.'});
                  } else {
                    redisClient.set(user, JSON.stringify({token:redisKey, forwardUrl:req.body.forwardUrl}));
                    axios.post(req.body.forwardUrl, {message:'successfully added forwardurl to your granted token.'});
                    return res.status(200).json({message:'successfully added forwardurl to your granted token.'});
                  }                    
                }
                redisClient.del(redisKey);
                if(isRedisKeyUserObj) {                    
                    redisClient.del((JSON.parse(reply)).token);
                } else {
                    redisClient.del((reply.split('-')[0]));
                }
                
                if(req.body.forwardUrl) {
                    axios.post(req.body.forwardUrl, {message:'authorisation denied. Token expired or cannot be verified.'});
                }
                return res.status(400).json({message:'authorisation denied. Token expired or cannot be verified.'});
          } else {
              res.status(400).json({message:'authorisation denied. You have never authorised bruh!!.'});
          }
      });
    }catch(err) {
        console.error(err);
        res.status(500).json({message:'server error'});
    }  
});

  app.post('/receive/secure', (req, res) => {
      try {
        let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
        if (token && token.startsWith('Bearer ')) {
            // Remove Bearer from string
            token = token.slice(7, token.length);
        }
        if (!token) {
            if(req.body.forwardUrl) {
                axios.post(req.body.forwardUrl, { message: 'Unauthorized. Token not found.' });
            }
            return res.status(403).json({ message: 'Unauthorized. Token not found.' });
        }
        return redisClient.get(token, function (err, reply) {
            console.log("found token:",reply);
            if (reply != null) {
                let isValid = false;
                let decoded;
                try {
                    decoded = jwt.verify(token, process.env.JWT_SIGNING_KEY);
                    if (decoded.grantedToken) {
                        console.log('valid token', decoded);
                        isValid = true;
                    } else {
                        console.log('invalid token, does not contain grantedtoken or forward url', decoded);
                    }
                } catch (err) {
                    console.error('failed to verify token: ',err);
                }
                if(isValid) {
                    if(req.body.forwardUrl) {
                        axios.post(req.body.forwardUrl, req.body);
                    } else if(reply) {
                        const user = reply.split('-')[0];
                        console.log('user from token:',user);
                        redisClient.get(user, function(err, reply) {
                            const replyObject = JSON.parse(reply);
                            console.log('value against user', replyObject);
                            if(replyObject.forwardUrl) {
                                axios.post(replyObject.forwardUrl, req.body);
                            }
                        });
                    }
                    return res.status(200).json(req.body);
                }
                redisClient.del(token);
                redisClient.del(reply.split('-')[0]);
                if(req.body.forwardUrl) {
                    axios.post(req.body.forwardUrl, {message:'authorisation denied. Token expired or cannot be verified.'});
                }
                return res.status(400).json({message:'authorisation denied. Token expired or cannot be verified.'});
            } else {
                res.status(400).json({message:'authorisation denied. You have never authorised bruh!!.'});
            }
        });
      }catch(err) {
          console.error(err);
      }
    
    
  });

  app.get('/auth/user/get', (req, res) => {
    let clientId = req.headers['authorization'];
    if(clientId) {
        return redisClient.get(clientId, function(err, reply) {
            if(reply != null) {
                return res.status(200).json(JSON.parse(reply));
            } 
            return res.status(404).json({message:'not found'});
        });
    }
  });

  app.post('/auth/token/remove', (req, res) => {
      try {
        let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
        if (token && token.startsWith('Bearer ')) {
            // Remove Bearer from string
            token = token.slice(7, token.length);
        }
        console.log("remove: ",token);
        if (!token) {
            if(req.body.forwardUrl) {
                axios.post(req.body.forwardUrl, { message: 'Unauthorized' });
            }
            return res.status(403).json({ message: 'Unauthorized' });
        }
        return redisClient.del(token, function (err, response) {
            if (response === 1) {
                if(req.body.forwardUrl) {
                    axios.post(req.body.forwardUrl, { message: 'removed successfully' });
                }
                try {
                    const userpass = jwt.decode(token);
                    if(userpass && userpass.user) {
                        redisClient.del(userpass.user);
                    }                    
                } catch(err) {
        
                }
                return res.status(200).json({message:'removed successfully'});
            } else {
                if(req.body.forwardUrl) {
                    axios.post(req.body.forwardUrl, { message: 'cannot remove' });
                } 
                return res.status(400).json({message:'cannot remove'});
            }
        });
      }catch(err) {
          console.error(err);
      }
    
    
  });

  app.post('/auth/token/removeall', (req,res) => {
      try {
        let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
        if (token && token.startsWith('Bearer ')) {
            // Remove Bearer from string
            token = token.slice(7, token.length);
        }
        if(token !== 'aliremovesall') {
            return res.status(400).json({message:'failed to remove all, you are not authorised for this operation'});
        }
        redisClient.flushdb( function (err, succeeded) {
            console.log(succeeded); // will be true if successfull
            if(succeeded) {
                return res.status(200).json({message:'removed all successfully'});
            } else {
                return res.status(400).json({message:'failed to remove all, sorry bruh!!'});
            }
        });

      }catch(err) {
        console.error(err);
      }
  });

  app.listen(port, () => {
    console.log(`OAuthServer started and listening on port ${port}`);
  });