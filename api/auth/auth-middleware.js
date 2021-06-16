const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken")
const User = require("../users/users-model")

const restricted = (req, res, next) => {
const token = req.headers.authorization

  if (token) {
    jwt.verify(token,JWT_SECRET,(err, decoded) => {
if (err) {
  res.status(401).json({message:"Token invalid"})
}else{
  req.decodedJwt = decoded
  next()
}
    })
  }else{
    res.status(401).json({message:"Token required"})
  }
}

const only = role_name => (req, res, next) => {
  
  if (role_name === req.decodedJwt.role_name) {
    next()
  }else{
    res.status(403).json({message:"This is not for you"})
  }
}


const checkUsernameExists = async (req, res, next) => {
  const {username} = req.body

try{
  const user = await User.findBy({username})
  if (!user){
    res.status(401).json({message:"Invalid credentials"})
  }else{
    next()
  }
}catch(err){
  next(err)
}}

const validateRoleName = (req, res, next) => {
  
 const {role_name} = req.body
  try{
     if (role_name === undefined || role_name.trim() === ""){
     req.body.role_name = 'student'
     next()
    } else if (role_name.trim() === 'admin'){
res.status(422).json({message:"Role name can not be admin"})
    } else if (role_name.trim().length > 32){
res.status(422).json({message:"Role name can not be longer than 32 chars"})
    }else{
      req.body.role_name = role_name.trim()
        next()
  }
    }catch(err){
     next(err)
   }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
