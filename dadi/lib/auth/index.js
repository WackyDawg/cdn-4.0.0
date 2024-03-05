const jwt = require('jsonwebtoken')
const logger = require('@dadi/logger')
const path = require('path')
const ejs = require('ejs')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const fs = require('fs').promises
var persist = require('node-persist')
var uuid = require('uuid')

const config = require(path.join(__dirname, '/../../../config.js'))
const help = require(path.join(__dirname, '/../help'))
const User = mongoose.model('User', {
  clientId: String,
  secret: String
})
function mustAuthenticate(requestUrl) {
  // Allow internal requests.
  if (requestUrl.indexOf('/_dadi') === 0) {
    return false
  }

  if (
    requestUrl.indexOf('/api/upload') > -1 &&
    config.get('upload.requireAuthentication') === false
  ) {
    return false
  }

  // All /api requests must be authenticated.
  return requestUrl.indexOf('/api') === 0
}

// This attaches middleware to the passed in app instance
module.exports = function(router) {
  const tokenRoute = '/token'
  const installRoute = '/setup'
  const loginRoute = '/login'

  mongoose.connect(
    'mongodb+srv://julian1234:password2005@cluster0.oyimqiz.mongodb.net/cdn',
    {
      useNewUrlParser: true,
      useUnifiedTopology: true
    }
  )

  // Installation Route
  router.post(installRoute, async (req, res) => {
    const {clientId, secret} = req.body

    const existingUser = await User.findOne({clientId}).maxTimeMS(20000)
    if (existingUser) {
      res.status(400).send({message: 'User Already Exists'})
    }

    const hashedSecret = await bcrypt.hash(secret, 10)

    const newUser = new User({clientId, secret: hashedSecret})
    await newUser.save()

    res.send({message: 'User created Successfully'})
  })

  // Login Route
  // Login route
  router.post(loginRoute, async (req, res) => {
    const {clientId, secret} = req.body

    // Find the user by clientId
    const user = await User.findOne({clientId})

    // Check if the user exists and the password is correct
    if (user && (await bcrypt.compare(secret, user.secret))) {
      const payload = {domain: req.__domain}

      // Sign a JWT token.
      jwt.sign(
        payload,
        config.get('auth.privateKey', req.__domain),
        {
          expiresIn: config.get('auth.tokenTtl', req.__domain)
        },
        (err, token) => {
          if (err) {
            logger.error({module: 'auth'}, err)
            return res.status(500).json({message: 'Internal Server Error'})
          }

          res.setHeader('Content-Type', 'application/json')
          res.setHeader('Cache-Control', 'no-store')
          res.setHeader('Pragma', 'no-cache')
          res.json({
            accessToken: token,
            tokenType: 'Bearer',
            expiresIn: config.get('auth.tokenTtl')
          })
        }
      )
    } else {
      return fail('NoAccess', res)
    }
  })

  // Authorize
  router.use((req, res, next) => {
    // Let requests for tokens through, along with endpoints configured
    // to not use authentication.
    if (req.url === tokenRoute || !mustAuthenticate(req.url)) {
      return next()
    }

    // Require an authorization header for every request.
    if (!(req.headers && req.headers.authorization)) {
      return fail('NoToken', res)
    }

    // Strip token value out of request headers.
    const parts = req.headers.authorization.split(' ')

    // Headers should be `Authorization: Bearer <%=tokenvalue%>`
    const token =
      parts.length === 2 && /^Bearer$/i.test(parts[0]) ? parts[1] : null

    if (!token) {
      return fail('NoToken', res)
    }

    jwt.verify(
      token,
      config.get('auth.privateKey', req.__domain),
      (err, decoded) => {
        if (err || decoded.domain !== req.__domain) {
          return fail('InvalidToken', res)
        }

        return next()
      }
    )
  })

  router.get('/setup', async (req, res) => {
    const renderedHtml = await renderTemplate('register', {message: ''})
    res.writeHead(200, {'Content-Type': 'text/html'})
    res.end(renderedHtml)
  })

  router.get('/login', async (req, res) => {
    const renderedHtml = await renderTemplate('login', {message: ''})
    res.writeHead(200, {'Content-Type': 'text/html'})
    res.end(renderedHtml)
  })

  // Setup token service.
  router.use(tokenRoute, (req, res, next) => {
    const method = req.method && req.method.toLowerCase()

    if (method !== 'post') {
      return next()
    }

    const clientId = req.body.clientId
    const secret = req.body.secret

    // Fail if the auth.clientId or auth.secret haven't been set.
    if (!clientId || !secret) {
      return fail('NoAccess', res)
    }

    // Fail if the auth.privateKey hasn't been set.
    if (!config.get('auth.privateKey')) {
      return fail('NoPrivateKey', res)
    }

    // Fail if the auth.clientId and auth.secret don't match the configured values.
    if (
      clientId !== config.get('auth.clientId', req.__domain) ||
      secret !== config.get('auth.secret', req.__domain)
    ) {
      return fail('NoAccess', res)
    }

    const payload = {
      domain: req.__domain
    }

    // Sign a JWT token.
    jwt.sign(
      payload,
      config.get('auth.privateKey', req.__domain),
      {
        expiresIn: config.get('auth.tokenTtl', req.__domain)
      },
      (err, token) => {
        if (err) {
          logger.error({module: 'auth'}, err)

          return fail('JWTError', res)
        }

        res.setHeader('Content-Type', 'application/json')
        res.setHeader('Cache-Control', 'no-store')
        res.setHeader('Pragma', 'no-cache')
        res.end(
          JSON.stringify({
            accessToken: token,
            tokenType: 'Bearer',
            expiresIn: config.get('auth.tokenTtl')
          })
        )
      }
    )
  })

  // Helper function to render EJS templates
  async function renderTemplate(templateName, data) {
    const templatePath = path.join(
      __dirname,
      '../../../public/auth',
      'views',
      `${templateName}.ejs`
    )
    const templateContent = await fs.readFile(templatePath, 'utf-8')
    return ejs.render(templateContent, data)
  }

  function fail(type, res) {
    switch (type) {
      case 'NoToken':
        res.setHeader(
          'WWW-Authenticate',
          'Bearer, error="no_token", error_description="No access token supplied"'
        )
        break
      case 'InvalidToken':
        res.setHeader(
          'WWW-Authenticate',
          'Bearer, error="invalid_token", error_description="Invalid or expired access token"'
        )
        break
      case 'NoPrivateKey':
        res.setHeader(
          'WWW-Authenticate',
          'Bearer, error="no_private_key", error_description="No private key configured in auth.privateKey"'
        )
        break
      default:
        res.setHeader('WWW-Authenticate', 'Bearer realm="/token"')
    }

    return help.displayUnauthorizedError(res)
  }
}
